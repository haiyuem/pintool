/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

//
// This tool prints each RTN's entry and exit point wht the global instruction count. 
// This tool is thread safe. 
//

#include <fstream>
#include <iomanip>
#include <iostream>
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
bool selected_RTN = false;
PIN_LOCK pinLock;
UINT64 global_ins_count;

VOID rtn_before(const string rtn_name_to_parse_str, const string rtn_name, ADDRINT rtn_addr, UINT32 inscount_in_RTN, THREADID threadid) { 
    if ((rtn_name_to_parse_str == rtn_name) || (rtn_name_to_parse_str == "")){
        selected_RTN = true;
        PIN_GetLock(&pinLock, PIN_GetTid());
        OutFile << "RTN START addr: " << hex << rtn_addr << "\t" << rtn_name << endl;  
        PIN_ReleaseLock(&pinLock);
    }
}

VOID rtn_after(const string rtn_name_to_parse_str, const string rtn_name, ADDRINT rtn_addr, UINT32 inscount_in_RTN, THREADID threadid) {
    if (selected_RTN){
        PIN_GetLock(&pinLock, PIN_GetTid());
        global_ins_count += inscount_in_RTN;
        OutFile << "RTN FINISH addr: " << hex << rtn_addr << "\t" << rtn_name << " RTN Ins Count: " << dec << inscount_in_RTN << " Total Inst Count: " << global_ins_count << endl;
        PIN_ReleaseLock(&pinLock);
    }
    if (rtn_name_to_parse_str == rtn_name){
        selected_RTN = false;
    }
}

// Pin calls this function every time a new rtn is executed
VOID Routine(RTN rtn, VOID* rtn_name_to_parse)
{
    KNOB< string >* rtn_name_to_parse_ptr = (KNOB< string >*)rtn_name_to_parse;
    string rtn_name_to_parse_str = rtn_name_to_parse_ptr->Value().c_str();
    // if (RTN_Name(rtn).find(".text") != std::string::npos){
    // if ((rtn_name_to_parse_str == "") || (RTN_Name(rtn) == rtn_name_to_parse_str)){ 
        RTN_Open(rtn);

        // Insert a call at the entry point of a routine to increment the call count
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)rtn_before, 
        IARG_PTR, new string(rtn_name_to_parse_str),
        IARG_PTR, new string(RTN_Name(rtn)),
        IARG_ADDRINT, RTN_Address(rtn),
        IARG_UINT32, RTN_NumIns(rtn),
        IARG_THREAD_ID,
        IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)rtn_after, 
        IARG_PTR, new string(rtn_name_to_parse_str),
        IARG_PTR, new string(RTN_Name(rtn)),
        IARG_ADDRINT, RTN_Address(rtn),
        IARG_UINT32, RTN_NumIns(rtn),
        IARG_THREAD_ID,
        IARG_END);


        
        RTN_Close(rtn);
    // }
}

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "rtn_global_inscount.out", "specify output file name");
KNOB< string > rtn_name_to_parse(KNOB_MODE_WRITEONCE, "pintool", "rtn_name_to_parse", "", "Specify RTN name to parse; if none, will parse all RTNs");

// This function is called when the application exits
// It prints the name and count for each procedure
VOID Fini(INT32 code, VOID* v)
{
    if (OutFile.is_open()) OutFile.close();
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
    // Initialize lock 
    PIN_InitLock(&pinLock);
    OutFile.open(KnobOutputFile.Value().c_str());

    // Register Routine to be called to instrument rtn
    RTN_AddInstrumentFunction(Routine, &rtn_name_to_parse);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
