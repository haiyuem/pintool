/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

//
// Print [memaddr, data value] as 2d arrays for cluster analysis
//

#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string.h>
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
bool going = false;
UINT64 instrCount = 0;
bool write_out_trace = false;
bool print = true;
// bool print_ins = false;
int interval = 100000000;

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "load_val_hex_print.out", "specify output file name");
KNOB< string > KnobTraceFile(KNOB_MODE_WRITEONCE, "pintool", "trace", "trace", "specify trace name");
KNOB< string > rtn_name_to_parse(KNOB_MODE_WRITEONCE, "pintool", "rtn_name_to_parse", "", "Specify RTN name to parse; if none, will parse all RTNs");

KNOB<UINT64> KnobSkipInstructions(KNOB_MODE_WRITEONCE, "pintool", "s", "0", "How many instructions to skip before tracing begins");

KNOB<UINT64> KnobTraceInstructions(KNOB_MODE_WRITEONCE, "pintool", "i", "0", "How many instructions to trace; enter 0 for unlimited");

BOOL ShouldWrite()
{
    if (going) {
        ++instrCount;
    }
//   OutFile << dec << "count: " << instrCount << " " << KnobTraceInstructions.Value() << " " << KnobSkipInstructions.Value() << " " <<endl;
    UINT64 trace_count = KnobTraceInstructions.Value();
    //if use KnobTraceInstructions directly, does not work, don't know why
    if (trace_count == 0) return (instrCount > KnobSkipInstructions.Value());
    else return (instrCount > KnobSkipInstructions.Value()) && (instrCount <= (trace_count + KnobSkipInstructions.Value()));
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

VOID ReadContent(ADDRINT ins_addr, VOID* memread_addr, UINT32 memread_size, const string ins_str)
{
    if (going) {
        if (instrCount % interval == 0){
            // OutFile << dec << "Processing Instruction " << instrCount << "..." << endl;
            OutFile.close();
            std::ostringstream filename;
            UINT64 actual_count = instrCount + KnobSkipInstructions.Value();
            filename << dec << KnobOutputFile.Value().c_str() << "_" << actual_count << "-" << (actual_count+interval) << ".csv";
            OutFile.open(filename.str());
        }
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
        assert(read_size == (size_t)memread_size);

        if (write_out_trace) ByteFile.write((char*)&value, 8);
        if (print) OutFile << dec << (UINT64)memread_addr << ", " << value << endl;
        // OutFile << dec << value << endl;
    }
}

// Pin calls this function every time a new rtn is executed
VOID Routine(RTN rtn, VOID* rtn_name_to_parse)
{

    KNOB< string >* rtn_name_to_parse_ptr = (KNOB< string >*)rtn_name_to_parse;
    string rtn_name_to_parse_str = rtn_name_to_parse_ptr->Value().c_str();
    // if (RTN_Name(rtn).find(".text") != std::string::npos){
    if ((rtn_name_to_parse_str == "") || (RTN_Name(rtn) == rtn_name_to_parse_str)){ 
        RTN_Open(rtn);

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

        // For each instruction of the routine
        for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
        {
            // Insert a call to docount to increment the instruction counter for this rtn
            //exclude prefetch for lane_det
            if (INS_IsMemoryRead(ins) &&  (!INS_IsPrefetch(ins)) && (INS_Disassemble(ins).find("gather") == std::string::npos)){
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
            // else {
            //     INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount_ins, 
            //     IARG_PTR, &(rc->_icount), 
            //     IARG_PTR, new string(INS_Disassemble(ins)),
            //     IARG_INST_PTR,
            //     IARG_END);
            // }
            
        }

        RTN_Close(rtn);
    }
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
    // std::ostringstream filename;
    // filename << dec << KnobOutputFile.Value().c_str() << "_0-" << interval << ".csv";
    // OutFile.open(filename.str());
    OutFile.open(KnobOutputFile.Value().c_str());
    std::ostringstream filename1;
    filename1 << dec << KnobTraceFile.Value().c_str() << "_0-" << interval << ".csv";
    ByteFile.open(filename1.str());

    // Register Routine to be called to instrument rtn
    RTN_AddInstrumentFunction(Routine, &rtn_name_to_parse);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
