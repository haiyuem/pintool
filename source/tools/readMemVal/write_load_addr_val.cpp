/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

//
// Print [memaddr, data value] as 2d arrays for cluster analysis
//

/*
* 2023/07 HM: This file generates the trace for a cluster-based python profiler to detect the data value commonality level in a program. 
* This trace is load-only. It will write out rows of ['Index', 'PC', 'Data Addr', 'Data Value', 'Diff Source'] for each memory read. The Python script will then post-process the trace, find similar values and report the level of data value locality. 
* "Diff Source" is used to detect silent stores. Note: ** This code only writes 1 when it sees a store to separate the case where daddr and val both match. If this is the first time the value is loaded, "Diff Source" will be 0 and the entry will still count as a different source. This is handled in the python script. 
*/

#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string.h>
#include <unordered_map>
#include "pin.H"
using std::cerr;
using std::dec;
using std::endl;
using std::hex;
using std::ofstream;
using std::setw;
using std::string;

ofstream OutFile;
ofstream ByteFile;
ofstream debugfile;
bool going = false;
bool write_out_trace = false;
bool print = true;
// bool print_ins = false;
// this is RTN-aware instruction count regardless of skips
UINT64 instrCount = 0;
// this is global instruction count regardless of skips and RTNs
UINT64 progInstrCount = 0;
// this is the number of memory reads
UINT64 memReadCount = 0;
bool print_progInstrCount = false;
// This map will store the current value at each memory address
// std::unordered_map<ADDRINT, UINT64> memValueMap;
//for detecting silent store
std::unordered_map<ADDRINT, char> last_operation;

// Global storage for last write address and size
// static VOID* lastWriteAddr;
// static UINT32 lastWriteSize = 0;

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "invalid", "specify output file name");
KNOB< string > KnobTraceFile(KNOB_MODE_WRITEONCE, "pintool", "trace", "invalid", "specify trace name - binary dump");
// Whether to print out debug file
KNOB<bool> KnobDebug(KNOB_MODE_WRITEONCE, "pintool", "d", "0", 
        "Whether to print out debug info in another file");
KNOB<std::string> KnobDebugFile(KNOB_MODE_WRITEONCE,  "pintool", "debug_file_name", "champsim.trace.debug", 
        "specify file name for human-readable output for debugging");
KNOB< string > rtn_name_to_parse(KNOB_MODE_WRITEONCE, "pintool", "rtn_name_to_parse", "", "Specify RTN name to parse; if none, will parse all RTNs");

KNOB<UINT64> KnobSkipInstructions(KNOB_MODE_WRITEONCE, "pintool", "s", "0", "How many instructions to skip before tracing begins");
KNOB<UINT64> KnobTraceInstructions(KNOB_MODE_WRITEONCE, "pintool", "ti", "0", "How many instructions to trace; enter 0 for unlimited");
KNOB<UINT64> KnobJumpInstructions(KNOB_MODE_WRITEONCE, "pintool", "j", "0", "How many instructions to jump over (skipped) after each traced interval; enter 0 for no jump");
KNOB<UINT64> KnobInterval(KNOB_MODE_WRITEONCE, "pintool", "i", "0", "Interval for each trace (trace length) in number of instructions; enter 0 for unspecified (default=0)");

VOID Count(){
    ++progInstrCount;
}

BOOL ShouldWrite()
{
    if (going) {
        ++instrCount;
        UINT64 trace_count = KnobTraceInstructions.Value();
        UINT64 skip_count = KnobSkipInstructions.Value();
        UINT64 jump_count = KnobJumpInstructions.Value();
        UINT64 interval = KnobInterval.Value();
        // check that count does not exceed maximum traced instructions
        if ((trace_count == 0) || (progInstrCount < (trace_count + skip_count))){
            //check that count exceeds minimum traced instructions (skip phase)
            if (progInstrCount >= skip_count){
                //check that inst is not in the jump region: 
                if ((interval + jump_count) == 0) return true;
                if (((progInstrCount - skip_count) % (interval + jump_count)) < interval){
                    if ((progInstrCount - skip_count) % (interval + jump_count) == 0){
                        // OutFile << dec << "Processing Instruction " << progInstrCount << "..." << endl;
                        if (KnobOutputFile.Value() != "invalid"){
                            OutFile.close();
                            std::ostringstream outfilename;
                            outfilename << dec << KnobOutputFile.Value().c_str() << "_" << progInstrCount << "-" << (progInstrCount+interval) << ".csv";
                            OutFile.open(outfilename.str().c_str());
                        }
                        if (KnobTraceFile.Value() != "invalid"){
                            ByteFile.close();
                            std::ostringstream binfilename;
                            binfilename << dec << KnobTraceFile.Value().c_str() << "_" << progInstrCount << "-" << (progInstrCount+interval);
                            ByteFile.open(binfilename.str().c_str());
                        }
                    }
                    return true;
                }
            }
        }
    }
    return false;
    //if use KnobTraceInstructions directly, does not work, don't know why
    // if (trace_count == 0) return (progInstrCount > KnobSkipInstructions.Value());
    // else return (progInstrCount > KnobSkipInstructions.Value()) && (progInstrCount <= (trace_count + KnobSkipInstructions.Value()));
}

VOID docount_rtn(const string rtn_name_to_parse_str, const string rtn_name, ADDRINT rtn_addr) { 
    if ((rtn_name_to_parse_str == rtn_name) || (rtn_name_to_parse_str == "")){
        going = true;
    }
    // if (going){
    //     OutFile << "RTN START addr: " << hex << rtn_addr << "\t" << rtn_name << endl;
    // }
}

VOID rtn_after(const string rtn_name_to_parse_str, const string rtn_name, ADDRINT rtn_addr) {
    // if (going){
    //     OutFile << "RTN FINISH addr: " << hex << rtn_addr << "\t" << rtn_name << endl;
    // }
    if ((rtn_name_to_parse_str == rtn_name) && going){
        going = false;
    }
}

/* ===================================================================== */
// Debug: prints out instructions and verbose info
/* ===================================================================== */
void Debug(ADDRINT pc, const string ins_str)
{
    //add printing here 
    debugfile << dec << "Ins Count: " << progInstrCount << " Mem Read Count: " << memReadCount << " " << hex << "PC: " << pc << " " << ins_str << endl;
}

VOID ReadContent(ADDRINT ins_addr, VOID* memread_addr, UINT32 memread_size, const string ins_str)
{
    if (going) {
        //increment mem read count
        memReadCount++;
        // if (print_progInstrCount) OutFile << dec << progInstrCount << endl;
        // UINT64 value = 0;
        // PIN_SafeCopy(&value, memread_addr, memread_size);
        // OutFile << hex << "\tIns addr: " << ins_addr << "\t" << ins << "\tMemAddr: " << memread_addr << "\t Size: " << memread_size << "\tValue:" << (unsigned long long) value << endl;
        // std::bitset<64>value_bin(value);
        // OutFile << value_bin <<endl;
        // OutFile << hex <<value <<endl;
    

        // if (print) OutFile << hex << "MemRead: PC: " << ins_addr << " " << ins_str << endl;
        if (write_out_trace) ByteFile.write((char*)(&ins_addr), 8);
        if (write_out_trace) ByteFile.write((char*)(&memread_addr), 8);

        UINT64 value = 0;
        size_t read_size = PIN_SafeCopy((VOID*)(&value), (VOID*)memread_addr, memread_size);
        // assert(read_size == (size_t)memread_size);
        if (read_size == (size_t)memread_size){

            // Align with cache line size 
            ADDRINT memread_addr1 = (ADDRINT)memread_addr - ((ADDRINT)memread_addr % 64);

            //check whether it's a load of different source
            bool load_is_diff_source = true;
            auto it = last_operation.find((ADDRINT)memread_addr1);
            if (it != last_operation.end()){
                if(it->second == 'R') {
                    load_is_diff_source = false;
                }
            }
            
            // Write down current op = Read
            last_operation[memread_addr1] = 'R';

            if (write_out_trace) ByteFile.write((char*)&value, 8);
            // if (print) OutFile << "\tmemread_addr:  " << memread_addr << " memread_size: " << memread_size << " val: " << value << endl;
            if (print) OutFile << dec << memReadCount << ", " << (UINT64)ins_addr << ", " << (UINT64)memread_addr << ", " << value << ", " << load_is_diff_source << endl;
            // OutFile << dec << value << endl;
        }
        
    }
}

// Just record the memory address of the store - will check if it's silent store in the Python code 
VOID RecordWriteAddr(ADDRINT memwrite_addr) {
    if (going){
        memwrite_addr = memwrite_addr - (memwrite_addr % 64);
        last_operation[memwrite_addr] = 'S';
    }
}

// Pin calls this function every time a new rtn is executed
VOID Routine(RTN rtn, VOID* rtn_name_to_parse)
{

    KNOB< string >* rtn_name_to_parse_ptr = (KNOB< string >*)rtn_name_to_parse;
    string rtn_name_to_parse_str = rtn_name_to_parse_ptr->Value().c_str();
    // if (RTN_Name(rtn).find(".text") != std::string::npos){
    
    RTN_Open(rtn);

    if ((rtn_name_to_parse_str == "") || (RTN_Name(rtn) == rtn_name_to_parse_str)){ 
        // RTN_Open(rtn);

        // Insert a call at the entry point of a routine to increment the call count
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)docount_rtn, 
        IARG_PTR, new string(rtn_name_to_parse_str),
        IARG_PTR, new string(RTN_Name(rtn)),
        IARG_ADDRINT, RTN_Address(rtn),
        IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)rtn_after, 
        IARG_PTR, new string(rtn_name_to_parse_str),
        IARG_PTR, new string(RTN_Name(rtn)),
        IARG_ADDRINT, RTN_Address(rtn),
        IARG_END);
    }
    // For each instruction of the routine
    for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
    {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)Count, IARG_END);
        // Track memory read instructions that need to be written out
        if (INS_IsMemoryRead(ins) &&  (!INS_IsPrefetch(ins)) && (INS_Disassemble(ins).find("gather") == std::string::npos) && (INS_Opcode(ins) != XED_ICLASS_TILELOADD)){
            //count total read instructions 
            if ((rtn_name_to_parse_str == "") || (RTN_Name(rtn) == rtn_name_to_parse_str)){
                //std::string instrString = INS_Disassemble(ins); 
                //fprintf("%s: ", instrString.c_str());
                INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)ShouldWrite, IARG_END);
                INS_InsertThenCall(ins,
                    IPOINT_BEFORE,
                    AFUNPTR(ReadContent),
                    IARG_INST_PTR,
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYREAD_SIZE, 
                    //IARG_REG_VALUE,
                    IARG_PTR, 
                    new string(INS_Disassemble(ins)),
                    IARG_END);
            } 
        } 
        if (INS_IsMemoryWrite(ins) && (INS_Disassemble(ins).find("scatter") == std::string::npos) && (INS_Opcode(ins) != XED_ICLASS_TILESTORED) && INS_IsValidForIpointAfter(ins)) { // Mark silent stores
            if ((rtn_name_to_parse_str == "") || (RTN_Name(rtn) == rtn_name_to_parse_str)){
                INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)ShouldWrite, IARG_END);
                INS_InsertThenCall(ins,
                    IPOINT_BEFORE,
                    (AFUNPTR)RecordWriteAddr,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
            }
        }
        // else {
        //     INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount_ins, 
        //     IARG_PTR, &(rc->_icount), 
        //     IARG_PTR, new string(INS_Disassemble(ins)),
        //     IARG_INST_PTR,
        //     IARG_END);
        // }

        //Debug function that prints out instructions in a readable form
        if (KnobDebug.Value()){
            INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)ShouldWrite, IARG_END);
            INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)Debug, 
            IARG_INST_PTR,
            IARG_PTR, new string(INS_Disassemble(ins)), //print out instruction string for debug
            IARG_END);
        }
    }

        // RTN_Close(rtn);
    // }
    RTN_Close(rtn);
}


// This function is called when the application exits
// It prints the name and count for each procedure
VOID Fini(INT32 code, VOID* v)
{
    if (OutFile.is_open())
    {
        OutFile.close();
    }
    if (ByteFile.is_open())
    {
        ByteFile.close();
    }
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This Pintool counts the number of times a routine is executed" << endl;
    cerr << "and the number of instructions executed in a routine" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char* argv[])
{
    // Initialize symbol table code, needed for rtn instrumentation
    PIN_InitSymbols();
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();
    std::ostringstream outfilename;
    UINT64 actual_count = KnobSkipInstructions.Value();
    // if output file is defined, write to output file
    if (KnobOutputFile.Value() != "invalid") {
        outfilename << dec << KnobOutputFile.Value().c_str() << "_" << actual_count << "-" << (actual_count+KnobInterval.Value()) << ".csv";
        OutFile.open(outfilename.str().c_str());
        // OutFile.open(KnobOutputFile.Value().c_str());
    }
    // if trace is defined (not needed for now), write to output file
    if (KnobTraceFile.Value() != "invalid") {
        std::ostringstream binfilename;
        binfilename << dec << KnobTraceFile.Value().c_str() << "_" << actual_count << "-" << (actual_count+KnobInterval.Value());
        ByteFile.open(binfilename.str().c_str());
    }

    //Debug file that writes out human-readable instructions
    if (KnobDebug.Value()) {debugfile.open(KnobDebugFile.Value().c_str());}

    // Register Routine to be called to instrument rtn
    RTN_AddInstrumentFunction(Routine, &rtn_name_to_parse);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
