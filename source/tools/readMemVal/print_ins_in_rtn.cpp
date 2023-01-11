/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

//print all instructions; if specified RTN, will only print out those in RTN 
//optionally, use count to print only the first [count] num of insns 

#include <iostream>
#include <fstream>
#include "pin.H"
using std::cerr;
using std::endl;
using std::ios;
using std::ofstream;
using std::string;
using std::hex;
using std::dec;

ofstream OutFile;
int count = 0;

VOID PrintIns(const string s, ADDRINT ins_addr)
{
    // count ++;
    // if (count > 1000) return;
    OutFile << "PC:" << ins_addr << "\tIns: " << s << endl;
}

VOID Routine(RTN rtn, VOID* rtn_name_to_parse)
{
    KNOB< string >* rtn_name_to_parse_ptr = (KNOB< string >*)rtn_name_to_parse;
    string rtn_name_to_parse_str = rtn_name_to_parse_ptr->Value().c_str();
    // if (RTN_Name(rtn).find("main") != std::string::npos){
    if ((rtn_name_to_parse_str == "") || (RTN_Name(rtn) == rtn_name_to_parse_str)){
        RTN_Open(rtn);
        
        OutFile << hex << "RTN base addr: 0x" << RTN_Address(rtn) << "\t" << RTN_Name(rtn) << endl;
        for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)){
            // if (INS_IsMemoryRead(ins)){
                INS_InsertCall(ins, 
                IPOINT_BEFORE,
                AFUNPTR(PrintIns),
                IARG_PTR, new string(INS_Disassemble(ins)), //ins string
                IARG_INST_PTR, //ins addr
                IARG_END
                );
            // }
        }
        RTN_Close(rtn);
    }
}

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "print_ins_in_rtn.out", "specify output file name");
KNOB< string > rtn_name_to_parse(KNOB_MODE_WRITEONCE, "pintool", "rtn_name_to_parse", "", "Specify RTN name to parse; if none, will parse all RTNs");

VOID Fini(INT32 code, VOID* v)
{
    OutFile << "#eof" << endl;
    OutFile.close();
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    // PIN_ERROR("This Pintool prints a trace of memory addresses\n" + KNOB_BASE::StringKnobSummary() + "\n");
    cerr << "Prints inst" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char* argv[])
{
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return Usage();

    OutFile.open(KnobOutputFile.Value().c_str());
    RTN_AddInstrumentFunction(Routine, &rtn_name_to_parse);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();

    return 0;
}
