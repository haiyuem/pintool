/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

//
// This will first print out all the RTNs the application run and then each unique instruction (op name) once
// This is used to get all the unique ops from the application 
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
static string _tabStr[0x1000];
static string _tabFirstIns[0x1000];


// Pin calls this function every time a new rtn is executed
VOID Routine(RTN rtn, VOID* rtn_name_to_parse)
{
    KNOB< string >* rtn_name_to_parse_ptr = (KNOB< string >*)rtn_name_to_parse;
    string rtn_name_to_parse_str = rtn_name_to_parse_ptr->Value().c_str();
    // if (RTN_Name(rtn).find("ATL_spNBmm_b1") != std::string::npos){
    if ((rtn_name_to_parse_str == "") || (RTN_Name(rtn) == rtn_name_to_parse_str)){
        RTN_Open(rtn);
        OutFile << "RTN base addr: 0x" << RTN_Address(rtn) << "\t" << RTN_Name(rtn) << endl;
        for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
        {
            _tabStr[INS_Opcode(ins)] = INS_Mnemonic(ins); 
     
        }
        RTN_Close(rtn);
    }

}

// This function is called when the application exits
// It prints the name and count for each procedure
VOID Fini(INT32 code, VOID* v)
{
    for (UINT32 i = 0; i < 1000; i++){
        if (!_tabStr[i].empty())
        OutFile << _tabStr[i] << "\t" << _tabFirstIns[i] << endl;
    }
    OutFile << "#eof" << endl;
    if (OutFile.is_open())
    {
        OutFile.close();
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

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "count_unique_ins.out", "specify output file name");
KNOB< string > rtn_name_to_parse(KNOB_MODE_WRITEONCE, "pintool", "rtn_name_to_parse", "", "Specify RTN name to parse; if none, will parse all RTNs");

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char* argv[])
{
    // Initialize symbol table code, needed for rtn instrumentation
    PIN_InitSymbols();
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();
    OutFile.open(KnobOutputFile.Value().c_str());
    // Register Routine to be called to instrument rtn
    RTN_AddInstrumentFunction(Routine, &rtn_name_to_parse);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
