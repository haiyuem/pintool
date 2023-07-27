/*
 *    Copyright 2023 The ChampSim Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs 
 *  and could serve as the starting point for developing your first PIN tool
 */

/*
 * 05/04/2023 HM: Add support to dump specific RTN and all the instructions called within the RTN 
 * Add support to write operand values for each instruction into trace 
 * Trace format: [original instruction][op1(64bit)][op2(64bit)][op3(64bit)][op4(64bit)]
 * value=0xdeadbeef means it's not a valid operand
 */

/*
 * 07/06/2023 HM: Fixed issue for reading value, now reads all instruction's operand values (max 4)
 * Differentiated regular 64-bits operands and xmm reg operands (4*32-bit single-precision FP), but still uses (first) 64 bits for now, need to change 
 * TODO: 1) separate regular and xmm operands  2) include mem load/store values (need to add a field in champsim)

 * 07/18/2023 HM: Only focusing on regular 64-bit registers and xmm registers (but the first 32 bits), ignoring all other types of regs for now, need to add later 

 * 07/21/2023 HM: make the code PIN thread-safe 

 * 07/24/2023 HM: merge gen_cluster_trace and gen_champsim_trace

 * 07/25/2023 HM: realized that the simpoint result is per thread, add thread inst count for thread 0 for shouldwrite
*/

#include "pin.H"
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <atomic>
#include <unordered_map>

#include "/scratch/gpfs/hm2595/champsim-datacomm/inc/trace_instruction.h"

using namespace std;

using trace_instr_format_t = datacomm_instr;

atomic<int> activeThreadCount(0);

/* ================================================================== */
// Global variables 
/* ================================================================== */

//global count, regardless of RTN
UINT64 global_progInstrCount = 0;
//inst count for RTN included
UINT64 global_tracedInstrCount = 0;
//number of memory reads (for gen_cluster_trace)
UINT64 global_memReadCount = 0;
//This is for thread0 only; align with simpoint output
UINT64 T0_progInstrCount = 0;
// This map stores what operation it is for the last access of the mem address, for detecting silent store
unordered_map<ADDRINT, char> last_operation;

// gen 2 traces: champsim trace and cluster trace
ofstream champsim_outfile;
ofstream cluster_outfile;
ofstream debugfile;

// trace_instr_format_t curr_instr;

int numThreads = 0;
PIN_LOCK pinLock;

// structure to store each instruction's information
class thread_data_t
{
  public:
    thread_data_t() : progInstrCount(0), tracedInstrCount(0), memReadCount(0), should_write(0), should_write_memread(0){}
    UINT64 progInstrCount;
    UINT64 tracedInstrCount;
    UINT64 memReadCount;
    trace_instr_format_t curr_instr;
    bool should_write; // Whether this instruction needs to be written out
    bool should_write_memread; // only applies to mem reads; for cluster trace
};

// key for accessing TLS storage in the threads. initialized once in main()
static TLS_KEY tls_key = INVALID_TLS_KEY;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobChampSimOutputFile(KNOB_MODE_WRITEONCE,  "pintool", "champsim_trace_output", "champsim.trace", 
        "specify file name for Champsim tracer output");
KNOB<string> KnobClusterOutputFile(KNOB_MODE_WRITEONCE,  "pintool", "cluster_trace_output", "cluster.trace", 
        "specify file name for Cluster tracer output");

// Whether to print out debug file
KNOB<bool> KnobDebug(KNOB_MODE_WRITEONCE, "pintool", "d", "0", 
        "Whether to print out debug info in another file");
KNOB<string> KnobDebugFile(KNOB_MODE_WRITEONCE,  "pintool", "debug_file_name", "champsim.trace.debug", 
        "specify file name for Champsim tracer human-readable output for debugging");

// TODO: merge cluster_gen's interval and jump mechanisms here
KNOB<UINT64> KnobSkipInstructions(KNOB_MODE_WRITEONCE, "pintool", "s", "0", 
        "How many instructions to skip before tracing begins");
KNOB<UINT64> KnobTraceInstructions(KNOB_MODE_WRITEONCE, "pintool", "ti", "0", 
        "How many instructions to trace");

//This option enables user to parse a specific RTN (function) with all its internal calls
KNOB< string > rtn_name_to_parse(KNOB_MODE_WRITEONCE, "pintool", "rtn_name_to_parse", "", "Specify RTN name to parse; if none, will parse all RTNs");

// ******THREAD FUNCTIONS*******

VOID ThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v)
{
    numThreads++;
    activeThreadCount++;
    cout << "Thread started: " << threadid << ", Total threads: " << activeThreadCount << endl;
    thread_data_t* tdata = new thread_data_t;
    if (PIN_SetThreadData(tls_key, tdata, threadid) == FALSE)
    {
        cerr << "PIN_SetThreadData failed" << endl;
        PIN_ExitProcess(1);
    }
}

VOID ThreadFini(THREADID threadid, const CONTEXT* ctxt, INT32 code, VOID* v)
{
    activeThreadCount--;
    cout << "Thread ended: " << threadid << ", Total threads: " << activeThreadCount << endl;
    thread_data_t* tdata = static_cast< thread_data_t* >(PIN_GetThreadData(tls_key, threadid));
    // *champsim_outfile << "Count[" << decstr(threadid) << "] = " << tdata->_count << endl;
    delete tdata;
}

/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
INT32 Usage()
{
    cerr << "This tool creates a register and memory access trace" << endl 
        << "Specify the ChampSim output trace file with -champsim_trace_output" << endl 
        << "Specify the Cluster output trace file with -cluster_trace_output" << endl 
        << "Specify the number of instructions to skip before tracing with -s" << endl
        << "Specify the number of instructions to trace with -t; default = 0 means no upper limit" << endl 
        << "Specify the RTN name to parse with -rtn_name_to_parse" << endl
        << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
// Routine tracker
/* ===================================================================== */

//keeps track of which instruction is written to the trace
bool selected_RTN = false;

VOID rtn_entry(const string rtn_name_to_parse_str, const string rtn_name, ADDRINT rtn_addr) { 
    if ((rtn_name_to_parse_str == rtn_name) || (rtn_name_to_parse_str == "")){
        selected_RTN = true;
    }
}

VOID rtn_exit(const string rtn_name_to_parse_str, const string rtn_name, ADDRINT rtn_addr) {
    if ((rtn_name_to_parse_str == rtn_name) && selected_RTN){
        selected_RTN = false;
    }
}

/* ===================================================================== */
// Debug: prints out instructions and verbose info
/* ===================================================================== */
void Debug(ADDRINT pc, const string ins_str, THREADID threadid, BOOL is_memoryread)
{
    thread_data_t* tdata = static_cast< thread_data_t* >(PIN_GetThreadData(tls_key, threadid));
    if (tdata->should_write){
        stringstream message;
        message << dec << "Thread: " << threadid << " Ins Count: " << tdata->progInstrCount << " " << "RTN Ins Count: " << tdata->tracedInstrCount << " " << hex << "PC: " << pc << " " << ins_str ;
        if (tdata->should_write_memread) message << " Mem Count: " << dec << tdata->memReadCount;
        if (threadid == 0) message << " Thread 0 Count: " << dec << T0_progInstrCount;
        message << endl;
        for (unsigned int nth_reg=0; nth_reg<NUM_INSTR_SOURCES; nth_reg++){
            REG r = (REG)(tdata->curr_instr.source_registers[nth_reg]);
            if (REG_valid(r)){
                message << dec << "Reg: " << REG_StringShort((REG)(tdata->curr_instr.source_registers[nth_reg])) << " Val: " << hex << tdata->curr_instr.operand_vals[nth_reg] << endl;
            }
        }
        // write all at once
        PIN_GetLock(&pinLock, threadid);
        debugfile << message.str();
        PIN_ReleaseLock(&pinLock);
    }
}

//This is to count the number of ins
VOID ShouldWrite(THREADID threadid, BOOL is_memoryread){
    // count how many instructions have passed in Thread 0; use that to control if shouldwrite or not 
    if (threadid == 0){
        T0_progInstrCount++;
    }
    thread_data_t* tdata = static_cast< thread_data_t* >(PIN_GetThreadData(tls_key, threadid));
    tdata->should_write = false;
    tdata->should_write_memread = false;
    PIN_GetLock(&pinLock, threadid);
    // global count of the application, regardless of any limitation
    ++global_progInstrCount;
    tdata->progInstrCount = global_progInstrCount;
    // this only applies to traced instructions: defined by RTN and skip/traced inst #
    PIN_ReleaseLock(&pinLock);
    if (selected_RTN) {
        bool is_traced = false;
        if (KnobTraceInstructions.Value() == 0) {
            is_traced = (T0_progInstrCount > KnobSkipInstructions.Value());
        }
        else {
            is_traced = ((T0_progInstrCount > KnobSkipInstructions.Value()) && (T0_progInstrCount <= (KnobTraceInstructions.Value() + KnobSkipInstructions.Value())));
        }
        if (is_traced){
            PIN_GetLock(&pinLock, threadid);
            ++global_tracedInstrCount;
            tdata->tracedInstrCount = global_tracedInstrCount;
            PIN_ReleaseLock(&pinLock);
            tdata->should_write = true;
            // if this is memory read, this is traced by cluster trace gen
            if (is_memoryread) {
                PIN_GetLock(&pinLock, threadid);
                ++global_memReadCount;
                tdata->memReadCount = global_memReadCount;
                PIN_ReleaseLock(&pinLock);
                tdata->should_write_memread = true;
            }
        }
    }
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

void ResetCurrentInstruction(VOID *ip, THREADID threadid)
{
    thread_data_t* tdata = static_cast< thread_data_t* >(PIN_GetThreadData(tls_key, threadid));
    if (tdata->should_write){
        tdata->curr_instr = {};
        tdata->curr_instr.ip = (unsigned long long int)ip;
    }
}

void WriteCurrentInstruction(THREADID threadid)
{
    thread_data_t* tdata = static_cast< thread_data_t* >(PIN_GetThreadData(tls_key, threadid));
    if (tdata->should_write){
        typename decltype(champsim_outfile)::char_type buf[sizeof(trace_instr_format_t)];
        memcpy(buf, &(tdata->curr_instr), sizeof(trace_instr_format_t));
        PIN_GetLock(&pinLock, threadid);
        champsim_outfile.write(buf, sizeof(trace_instr_format_t));
        PIN_ReleaseLock(&pinLock);
    }
}

void BranchOrNot(UINT32 taken, THREADID threadid)
{
    thread_data_t* tdata = static_cast< thread_data_t* >(PIN_GetThreadData(tls_key, threadid));
    if (tdata->should_write){
        tdata->curr_instr.is_branch = 1;
        tdata->curr_instr.branch_taken = taken;
    }
}

//This function is the common part of WriteValToSet (Source/Dest): put reg val into array
void WriteValToSet_HandleRegs(unsigned char* begin, unsigned char* end, thread_data_t* tdata, UINT32 r, CONTEXT* ctxt, REG reg) {
    auto set_end = find(begin, end, 0);
    auto found_reg = find(begin, set_end, r); // check to see if this register is already in the list
    *found_reg = r;
    //get index
    int nth_reg = distance(begin, found_reg);
    UINT8 regval[8];  // Buffer to hold register value
    PIN_GetContextRegval(ctxt, reg, regval);
    // Interpret the first 64 bits of the register value as a UINT64
    UINT64* val = reinterpret_cast<UINT64*>(regval);
    tdata->curr_instr.operand_vals[nth_reg] = *val;
}


//This function was used to put a reg/memop into a list
//WriteValToSet writes both reg names and vals; original WriteToSet func only works for mem ops (no vals for now, might add later)
// Use IARG_REG_CONST_REFERENCE (immediate analysis routine), not PIN_GetContextRegval (more flexible, can be used as long as we have context)
// separate source and dest functions because curr_instr is now a per-thread data struct and can't be accessed in instrumentation routines, so we cannot pass arbitrary array pointers as before, but have to identify specific array and size when putting values in 
void WriteValToSetSource(UINT32 r, CONTEXT* ctxt, REG reg, THREADID threadid)
{
    thread_data_t* tdata = static_cast<thread_data_t*>(PIN_GetThreadData(tls_key, threadid));
    if (tdata->should_write){
        unsigned char* begin = tdata->curr_instr.source_registers;
        unsigned char* end = tdata->curr_instr.source_registers + NUM_INSTR_SOURCES;
        WriteValToSet_HandleRegs(begin, end, tdata, r, ctxt, reg);
    }
}


void WriteValToSetDest(UINT32 r, CONTEXT* ctxt, REG reg, THREADID threadid)
{
    thread_data_t* tdata = static_cast< thread_data_t* >(PIN_GetThreadData(tls_key, threadid));
    if (tdata->should_write){
        unsigned char* begin = tdata->curr_instr.destination_registers;
        unsigned char* end = tdata->curr_instr.destination_registers + NUM_INSTR_DESTINATIONS;
        WriteValToSet_HandleRegs(begin, end, tdata, r, ctxt, reg);
    }
}

void WriteToSet_HandleRegs(unsigned long long int* begin, unsigned long long int* end, thread_data_t* tdata, ADDRINT r)
{
  auto set_end = find(begin, end, 0);
  auto found_reg = find(begin, set_end, r); // check to see if this register is already in the list
  *found_reg = r;
}

void WriteToSetSource(ADDRINT r, THREADID threadid){
    thread_data_t* tdata = static_cast< thread_data_t* >(PIN_GetThreadData(tls_key, threadid));
    if (tdata->should_write){
        unsigned long long int* begin = tdata->curr_instr.source_memory;
        unsigned long long int* end = tdata->curr_instr.source_memory + NUM_INSTR_SOURCES;
        WriteToSet_HandleRegs(begin, end, tdata, r);
    }
}

void WriteToSetDest(ADDRINT r, THREADID threadid){
    thread_data_t* tdata = static_cast< thread_data_t* >(PIN_GetThreadData(tls_key, threadid));
    if (tdata->should_write){
        unsigned long long int* begin = tdata->curr_instr.destination_memory;
        unsigned long long int* end = tdata->curr_instr.destination_memory + NUM_INSTR_DESTINATIONS;
        WriteToSet_HandleRegs(begin, end, tdata, r);
    }
}

void WriteImmediate(UINT64 immediate, THREADID threadid){
    thread_data_t* tdata = static_cast< thread_data_t* >(PIN_GetThreadData(tls_key, threadid));
    if (tdata->should_write){
        tdata->curr_instr.operand_vals[3] = immediate; 
    }
}

// ++++++++++++++++++++++++++++++++++++++++++
// gen cluster trace:
// ++++++++++++++++++++++++++++++++++++++++++
VOID ReadContent(ADDRINT ins_addr, VOID* memread_addr, UINT32 memread_size, const string ins_str, THREADID threadid)
{
    thread_data_t* tdata = static_cast< thread_data_t* >(PIN_GetThreadData(tls_key, threadid));
    if (tdata->should_write_memread){
        UINT64 value = 0;
        size_t read_size = PIN_SafeCopy((VOID*)(&value), (VOID*)memread_addr, memread_size);
        // assert(read_size == (size_t)memread_size);
        if (read_size == (size_t)memread_size){

            // Align with cache line size 
            ADDRINT memread_addr1 = (ADDRINT)memread_addr - ((ADDRINT)memread_addr % 64);

            //check whether it's a load of different source
            //TODO: THIS SILENT STORE DETECTOR IS NOT THREAD SAFE!! If instructions are not executed in order 
            bool load_is_diff_source = true;
            PIN_GetLock(&pinLock, threadid);
            auto it = last_operation.find((ADDRINT)memread_addr1);
            // Write down current op = Read
            last_operation[memread_addr1] = 'R';
            PIN_ReleaseLock(&pinLock);

            if (it != last_operation.end()){
                if(it->second == 'R') {
                    load_is_diff_source = false;
                }
            }

            PIN_GetLock(&pinLock, threadid);
            cluster_outfile << dec << tdata->memReadCount << ", " << (UINT64)ins_addr << ", " << (UINT64)memread_addr << ", " << value << ", " << load_is_diff_source << endl;
            PIN_ReleaseLock(&pinLock);
        }
        
    }
}

// Just record the memory address of the store - will check if it's silent store in the Python code 
VOID RecordWriteAddr(ADDRINT memwrite_addr, THREADID threadid) {
    thread_data_t* tdata = static_cast< thread_data_t* >(PIN_GetThreadData(tls_key, threadid));
    if (tdata->should_write){
        memwrite_addr = memwrite_addr - (memwrite_addr % 64);
        PIN_GetLock(&pinLock, threadid);
        last_operation[memwrite_addr] = 'S';
        PIN_ReleaseLock(&pinLock);
    }
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

// Is called for every instruction and instruments reads and writes
VOID Routine(RTN rtn, VOID* rtn_name_to_parse)
{
    //setup RTN name to parse
    KNOB< string >* rtn_name_to_parse_ptr = (KNOB< string >*)rtn_name_to_parse;
    string rtn_name_to_parse_str = rtn_name_to_parse_ptr->Value().c_str();

    RTN_Open(rtn);

    //for specific RTN, or for all RTNs (the entire program) if rtn_name_to_parse == ""
    // cannot filter rtn here because it might filter out unmatched sub-RTNs within matched RTNs
     
    // Insert a call at the entry and exit point of a routine to keep track of routine
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)rtn_entry, 
    IARG_PTR, new string(rtn_name_to_parse_str),
    IARG_PTR, new string(RTN_Name(rtn)),
    IARG_ADDRINT, RTN_Address(rtn),
    IARG_END);

    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)rtn_exit, 
    IARG_PTR, new string(rtn_name_to_parse_str),
    IARG_PTR, new string(RTN_Name(rtn)),
    IARG_ADDRINT, RTN_Address(rtn),
    IARG_END);

    for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)){
        // Count insts + check if this ins needed to be written
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ShouldWrite, IARG_THREAD_ID, IARG_BOOL, INS_IsMemoryRead(ins),IARG_END);

        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ResetCurrentInstruction, IARG_INST_PTR, IARG_THREAD_ID, IARG_END);

        // instrument branch instructions
        // TODO: temporarily exclude xbegin/xend instructions since IARG_BRANCH_TAKEN currently doesn't support that
        if(INS_IsBranch(ins) && (INS_Disassemble(ins).find("xend") == string::npos) && (INS_Disassemble(ins).find("xbegin") == string::npos)){
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BranchOrNot, IARG_BRANCH_TAKEN, IARG_THREAD_ID, IARG_END);
        }

        // instrument register reads
        UINT32 readRegCount = INS_MaxNumRRegs(ins);
        for(UINT32 i=0; i<readRegCount; i++) 
        {
            UINT32 regNum = INS_RegR(ins, i);
            // TODO: cannot deal with ymm regs (will error out with do not support reg k0 - AVX-512. possibly problems with IARG_REG_CONST_REFERENCE. Need to fix later)
            // if ((!(regNum >= REG_K0) && (regNum <= REG_K7)) && (!REG_is_zmm((REG)regNum))){
            // if (REG_is_gr32((REG)regNum) || REG_is_gr64((REG)regNum) || REG_is_xmm((REG)regNum)){
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteValToSetSource,
                    IARG_UINT32, regNum, 
                    IARG_CONTEXT,
                    IARG_ADDRINT, regNum,
                    IARG_THREAD_ID, 
                    IARG_END);
            // }
        }

        // instrument register writes
        UINT32 writeRegCount = INS_MaxNumWRegs(ins);
        for(UINT32 i=0; i<writeRegCount; i++) 
        {
            UINT32 regNum = INS_RegW(ins, i);
            // if ((!(regNum >= REG_K0) && (regNum <= REG_K7)) && (!REG_is_zmm((REG)regNum))){
            // if (REG_is_gr32((REG)regNum) || REG_is_gr64((REG)regNum) || REG_is_xmm((REG)regNum)){
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteValToSetDest,
                    IARG_UINT32, regNum, 
                    IARG_CONTEXT,
                    IARG_ADDRINT, regNum,
                    IARG_THREAD_ID, 
                    IARG_END);
            // }
        }

        // instrument immediate values
        INT32 opcount = INS_OperandCount(ins);
        for (INT32 i = 0; i < opcount; i++){
            if (INS_OperandIsImmediate(ins, i)){
                // ADDRINT value     = INS_OperandImmediate(ins, i);
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteImmediate,
                    IARG_UINT64, INS_OperandImmediate(ins, i),
                    IARG_THREAD_ID, 
                    IARG_END);
            }
        }

        // instrument memory reads and writes
        UINT32 memOperands = INS_MemoryOperandCount(ins);

        // Iterate over each memory operand of the instruction.
        for (UINT32 memOp = 0; memOp < memOperands; memOp++) 
        {
            if (INS_MemoryOperandIsRead(ins, memOp)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteToSetSource,
                    IARG_MEMORYOP_EA, memOp, IARG_THREAD_ID, IARG_END);
            }
            if (INS_MemoryOperandIsWritten(ins, memOp)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteToSetDest,
                    IARG_MEMORYOP_EA, memOp, IARG_THREAD_ID, IARG_END);
            }
        }

        // finalize each instruction with this function
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteCurrentInstruction, IARG_THREAD_ID, IARG_END);

        // ++++++++++++++++++++++++++++++++++++++++++
        // gen cluster trace: 
        if (INS_IsMemoryRead(ins) && (!INS_IsPrefetch(ins)) && (INS_Disassemble(ins).find("gather") == std::string::npos) && (INS_Opcode(ins) != XED_ICLASS_TILELOADD)){
            INS_InsertCall(ins,
                IPOINT_BEFORE,
                AFUNPTR(ReadContent),
                IARG_INST_PTR,
                IARG_MEMORYREAD_EA,
                IARG_MEMORYREAD_SIZE, 
                //IARG_REG_VALUE,
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_THREAD_ID, 
                IARG_END);
        } 
        if (INS_IsMemoryWrite(ins) && (INS_Disassemble(ins).find("scatter") == std::string::npos) && (INS_Opcode(ins) != XED_ICLASS_TILESTORED) && INS_IsValidForIpointAfter(ins)) { // Mark silent stores
            INS_InsertCall(ins,
                IPOINT_BEFORE,
                (AFUNPTR)RecordWriteAddr,
                IARG_MEMORYWRITE_EA,
                IARG_THREAD_ID, 
                IARG_END);
        }
        // ++++++++++++++++++++++++++++++++++++++++++
        
        //Debug function that prints out instructions in a readable form
        if (KnobDebug.Value()){
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)Debug, 
            IARG_INST_PTR,
            IARG_PTR, new string(INS_Disassemble(ins)), //print out instruction string for debug
            IARG_THREAD_ID, 
            IARG_BOOL, INS_IsMemoryRead(ins),
            IARG_END);
        }
    }
    RTN_Close(rtn); 
}


/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddFiniFunction function call
 */
VOID Fini(INT32 code, VOID *v)
{
    debugfile << dec << "Total Inst Count: " << global_progInstrCount << " TO Count: " << T0_progInstrCount << endl;
    if (champsim_outfile.is_open()) champsim_outfile.close();
    if (cluster_outfile.is_open()) cluster_outfile.close();
    if (debugfile.is_open()) debugfile.close();
}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments, 
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char *argv[])
{
    // Initialize symbol table code, needed for rtn instrumentation
    PIN_InitSymbols();
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 
    if( PIN_Init(argc,argv) )
        return Usage();
    // Initialize lock 
    PIN_InitLock(&pinLock);

    // open 2 trace files
    champsim_outfile.open(KnobChampSimOutputFile.Value().c_str(), ios_base::binary | ios_base::trunc);
    if (!champsim_outfile)
    {
      cout << "Couldn't open ChampSim output trace file. Exiting." << endl;
        exit(1);
    }
    cluster_outfile.open(KnobClusterOutputFile.Value().c_str(), ios_base::binary | ios_base::trunc);
    if (!cluster_outfile)
    {
      cout << "Couldn't open Cluster output trace file. Exiting." << endl;
        exit(1);
    }

    //Debug file that writes out human-readable instructions
    if (KnobDebug.Value()) {debugfile.open(KnobDebugFile.Value().c_str());}

    // Obtain a key for TLS storage.
    tls_key = PIN_CreateThreadDataKey(NULL);
    if (tls_key == INVALID_TLS_KEY)
    {
        cerr << "number of already allocated keys reached the MAX_CLIENT_TLS_KEYS limit" << endl;
        PIN_ExitProcess(1);
    }

    // Register ThreadStart to be called when a thread starts.
    PIN_AddThreadStartFunction(ThreadStart, NULL);

    // Register Fini to be called when thread exits.
    PIN_AddThreadFiniFunction(ThreadFini, NULL);

    // Register Routine to be called to instrument rtn
    RTN_AddInstrumentFunction(Routine, &rtn_name_to_parse);

    // Register function to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
