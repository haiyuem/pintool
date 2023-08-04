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

 * 07/26/2023 HM: Change this file to single thread (only track T0) to speed up for single thread apps
*/

#include "pin.H"
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <atomic>
#include <unordered_map>
#include "regvalue_utils.h"

#include <cstring>
#include <sstream>

#include "/home/haiyue/research/data_commonality/champsim-datacomm/inc/trace_instruction.h"

using namespace std;

using trace_instr_format_t = datacomm_instr;

atomic<int> activeThreadCount(0);

/* ================================================================== */
// Global variables 
/* ================================================================== */

// This map stores what operation it is for the last access of the mem address, for detecting silent store
unordered_map<ADDRINT, char> last_operation;

// gen 2 traces: champsim trace and cluster trace
ofstream champsim_outfile;
ofstream cluster_outfile;
ofstream debugfile;

int numThreads = 0;
UINT64 progInstrCount;
UINT64 tracedInstrCount;
UINT64 memReadCount;
trace_instr_format_t curr_instr;
bool should_write = false; // Whether this instruction needs to be written out
bool should_write_memread = false; // only applies to mem reads; for cluster trace

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

// ************* get rid of this for now because it will produce false instruction count - it will be half the instruction count compared to counting without selected_RTN. Don't know why...
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
void Debug(ADDRINT pc, const string ins_str, BOOL is_memoryread)
{
    if (should_write && (PIN_ThreadId() == 0)){
        stringstream message;
        message << dec << " Ins Count: " << progInstrCount << " " << "RTN Ins Count: " << tracedInstrCount << " " << hex << "PC: " << pc << " " << ins_str ;
        if (should_write_memread) message << " Mem Count: " << dec << memReadCount;
        message << endl;
        for (unsigned int nth_reg=0; nth_reg<NUM_INSTR_SOURCES; nth_reg++){
            REG r = (REG)(curr_instr.source_registers[nth_reg]);
            if (REG_valid(r)){
                message << dec << "Reg: " << REG_StringShort((REG)(curr_instr.source_registers[nth_reg])) << " Val: " << hex << curr_instr.operand_vals[nth_reg] << endl;
            }
        }
        // write all at once
        debugfile << message.str();
    }
}

//This is to count the number of ins
VOID ShouldWrite(BOOL is_memoryread){
    // global count of the application, regardless of any limitation
    // this only applies to traced instructions: defined by RTN and skip/traced inst #
    if (selected_RTN && (PIN_ThreadId() == 0)) {
        should_write = false;
        should_write_memread = false;
        ++progInstrCount;
        if (KnobTraceInstructions.Value() == 0) {
            should_write = (progInstrCount > KnobSkipInstructions.Value());
        }
        else {
            // quit if the program has run past the tracing range
            if ((progInstrCount > (KnobTraceInstructions.Value() + KnobSkipInstructions.Value())))
                PIN_ExitApplication(0);
            should_write = (progInstrCount > KnobSkipInstructions.Value());
        }
        if (should_write){
            ++tracedInstrCount;
            // if this is memory read, this is traced by cluster trace gen
            should_write_memread = is_memoryread;
            if (should_write_memread) {
                ++memReadCount;
            }
        }
    }
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

void ResetCurrentInstruction(VOID *ip)
{
    if (should_write && (PIN_ThreadId() == 0)){
        curr_instr = {};
        curr_instr.ip = (unsigned long long int)ip;
    }
}

void WriteCurrentInstruction()
{
    if (should_write && (PIN_ThreadId() == 0)){
        typename decltype(champsim_outfile)::char_type buf[sizeof(trace_instr_format_t)];
        memcpy(buf, &(curr_instr), sizeof(trace_instr_format_t));
        champsim_outfile.write(buf, sizeof(trace_instr_format_t)); 
    }
}

void BranchOrNot(UINT32 taken)
{
    if (should_write && (PIN_ThreadId() == 0)){
        curr_instr.is_branch = 1;
        curr_instr.branch_taken = taken;
    }
}

//This function was used to put a reg/memop into a list
//WriteValToSet writes both reg names and vals; original WriteToSet func only works for mem ops (no vals for now, might add later)
// Use PIN_GetContextRegval (more flexible, can be used as long as we have context)
void WriteValToSet(unsigned char* begin, unsigned char* end, UINT32 r, CONTEXT* ctxt, REG reg)
{
    if (should_write && (PIN_ThreadId() == 0)){
        auto set_end = std::find(begin, end, 0);
        auto found_reg = std::find(begin, set_end, r); // check to see if this register is already in the list
        *found_reg = r;
        //get index
        int nth_reg = std::distance(begin, found_reg);
        // UINT8 regval[8];  // Buffer to hold register value
        // PIN_GetContextRegval(ctxt, reg, regval);
        // // Interpret the first 64 bits of the register value as a UINT64
        // UINT64* val = reinterpret_cast<UINT64*>(regval);
        // curr_instr.operand_vals[nth_reg] = *val;
        // Uses PINTOOL_REGISTER from util, can hold any reg size, can interpret with different sizes
        PINTOOL_REGISTER val;
        PIN_GetContextRegval(ctxt, reg, reinterpret_cast< UINT8* >(&val));
        curr_instr.operand_vals[nth_reg] = val.qword[0];
    }
}

void WriteToSet(unsigned long long int* begin, unsigned long long int* end, ADDRINT r)
{
    if (should_write && (PIN_ThreadId() == 0)){
        auto set_end = std::find(begin, end, 0);
        auto found_reg = std::find(begin, set_end, r); // check to see if this register is already in the list
        *found_reg = r;
    }
}

void WriteImmediate(UINT64 immediate){
    if (should_write && (PIN_ThreadId() == 0)){
        curr_instr.operand_vals[3] = immediate; 
    }
}

// ++++++++++++++++++++++++++++++++++++++++++
// gen cluster trace:
// ++++++++++++++++++++++++++++++++++++++++++
VOID ReadContent(ADDRINT ins_addr, VOID* memread_addr, UINT32 memread_size, const string ins_str)
{
    if (should_write_memread && (PIN_ThreadId() == 0)){
        UINT64 value = 0;
        // this is to prevent bigger memread_size to cause seg faults - e.g. context switch instructions can have 380 bytes memread_size and it will cause false PCs
        if (memread_size > 8) memread_size = 8;
        size_t read_size = PIN_SafeCopy((VOID*)(&value), (VOID*)memread_addr, memread_size);
        assert(read_size == (size_t)memread_size);
        // Align with cache line size 
        ADDRINT memread_addr1 = (ADDRINT)memread_addr - ((ADDRINT)memread_addr % 64);

        //check whether it's a load of different source
        //TODO: THIS SILENT STORE DETECTOR IS NOT THREAD SAFE!! If instructions are not executed in order 
        bool load_is_diff_source = true;
        
        auto it = last_operation.find((ADDRINT)memread_addr1);
        // Write down current op = Read
        last_operation[memread_addr1] = 'R';

        if (it != last_operation.end()){
            if(it->second == 'R') {
                load_is_diff_source = false;
            }
        }
        cluster_outfile << dec << memReadCount << ", " << (UINT64)ins_addr << ", " << (UINT64)memread_addr << ", " << value << ", " << load_is_diff_source << endl;
    }
}

// Just record the memory address of the store - will check if it's silent store in the Python code 
VOID RecordWriteAddr(ADDRINT memwrite_addr) {
    if (should_write && (PIN_ThreadId() == 0)){
        memwrite_addr = memwrite_addr - (memwrite_addr % 64);
        last_operation[memwrite_addr] = 'S'; 
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
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ShouldWrite, IARG_BOOL, INS_IsMemoryRead(ins),IARG_END);

        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ResetCurrentInstruction, IARG_INST_PTR, IARG_END);

        // instrument branch instructions
        // TODO: temporarily exclude xbegin/xend instructions since IARG_BRANCH_TAKEN currently doesn't support that
        if(INS_IsBranch(ins) && (INS_Disassemble(ins).find("xend") == string::npos) && (INS_Disassemble(ins).find("xbegin") == string::npos)){
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BranchOrNot, IARG_BRANCH_TAKEN, IARG_END);
        }

        // instrument register reads
        UINT32 readRegCount = INS_MaxNumRRegs(ins);
        for(UINT32 i=0; i<readRegCount; i++) 
        {
            UINT32 regNum = INS_RegR(ins, i);
            // if (REG_is_gr32((REG)regNum) || REG_is_gr64((REG)regNum) || REG_is_xmm((REG)regNum)){
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteValToSet,
                IARG_PTR, curr_instr.source_registers, IARG_PTR, curr_instr.source_registers + NUM_INSTR_SOURCES,
                IARG_UINT32, regNum, 
                IARG_CONTEXT,
                IARG_ADDRINT, regNum,
                IARG_END);
            // }
        }

        // instrument register writes
        UINT32 writeRegCount = INS_MaxNumWRegs(ins);
        for(UINT32 i=0; i<writeRegCount; i++) 
        {
            UINT32 regNum = INS_RegW(ins, i);
            // if (REG_is_gr32((REG)regNum) || REG_is_gr64((REG)regNum) || REG_is_xmm((REG)regNum)){
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteValToSet,
                IARG_PTR, curr_instr.destination_registers, IARG_PTR, curr_instr.destination_registers + NUM_INSTR_DESTINATIONS,
                IARG_UINT32, regNum, 
                IARG_CONTEXT,
                IARG_ADDRINT, regNum,
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
                    IARG_END);
            }
        }

        // instrument memory reads and writes
        UINT32 memOperands = INS_MemoryOperandCount(ins);

        // Iterate over each memory operand of the instruction.
        for (UINT32 memOp = 0; memOp < memOperands; memOp++) 
        {
            if (INS_MemoryOperandIsRead(ins, memOp)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteToSet,
                    IARG_PTR, curr_instr.source_memory, IARG_PTR, curr_instr.source_memory + NUM_INSTR_SOURCES,
                    IARG_MEMORYOP_EA, memOp, IARG_END);
            }
            if (INS_MemoryOperandIsWritten(ins, memOp)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteToSet,
                    IARG_PTR, curr_instr.destination_memory, IARG_PTR, curr_instr.destination_memory + NUM_INSTR_DESTINATIONS,
                    IARG_MEMORYOP_EA, memOp, IARG_END);
            }
        }

        // finalize each instruction with this function
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteCurrentInstruction, IARG_END);

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
                IARG_END);
        } 
        if (INS_IsMemoryWrite(ins) && (INS_Disassemble(ins).find("scatter") == std::string::npos) && (INS_Opcode(ins) != XED_ICLASS_TILESTORED) && INS_IsValidForIpointAfter(ins)) { // Mark silent stores
            INS_InsertCall(ins,
                IPOINT_BEFORE,
                (AFUNPTR)RecordWriteAddr,
                IARG_MEMORYWRITE_EA,
                IARG_END);
        }
        // ++++++++++++++++++++++++++++++++++++++++++
        
        //Debug function that prints out instructions in a readable form
        if (KnobDebug.Value()){
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)Debug, 
            IARG_INST_PTR,
            IARG_PTR, new string(INS_Disassemble(ins)), //print out instruction string for debug
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
    debugfile << dec << "Total Inst Count: " << progInstrCount << " Traced Inst Count: " << tracedInstrCount << " Mem Count: " << memReadCount << endl;
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

    // Register Routine to be called to instrument rtn
    RTN_AddInstrumentFunction(Routine, &rtn_name_to_parse);

    // Register function to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
