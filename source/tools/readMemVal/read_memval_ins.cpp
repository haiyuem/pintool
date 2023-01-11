/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */


//print out all insns that are mem reads and the read value
//can use count to only print the first few

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

VOID ReadContent(VOID* ip, VOID* memread_addr, UINT32 memread_size, const string s)
{
    // count++;
    // if (count > 1000) return;
    UINT64 value = 0;
    PIN_SafeCopy(&value, memread_addr, memread_size);
    OutFile << hex << "InsAddr: " << ip << "\tIns: " << s << "\tMemAddr: " << memread_addr << "\t Size: " << memread_size << "\tValue:" << (unsigned long long) value << endl;
}

VOID Routine(RTN rtn, VOID* rtn_name_to_parse)
{
    KNOB< string >* rtn_name_to_parse_ptr = (KNOB< string >*)rtn_name_to_parse;
    string rtn_name_to_parse_str = rtn_name_to_parse_ptr->Value().c_str();
    // if (RTN_Name(rtn).find(".text") != std::string::npos){
    if ((rtn_name_to_parse_str == "") || (RTN_Name(rtn) == rtn_name_to_parse_str)){
        RTN_Open(rtn);
        OutFile << hex << "RTN base addr: 0x" << RTN_Address(rtn) << "\t" << RTN_Name(rtn) << endl;
        for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)){
            if (INS_IsMemoryRead(ins))
            {
                //std::string instrString = INS_Disassemble(ins); 
                //fprintf("%s: ", instrString.c_str());
                INS_InsertCall(ins,
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
        RTN_Close(rtn);
    }
}

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "read_memval_ins.out", "specify output file name");
KNOB< string > rtn_name_to_parse(KNOB_MODE_WRITEONCE, "pintool", "rtn_name_to_parse", "", "Specify RTN name to parse; if none, will parse all RTNs");

VOID Fini(INT32 code, VOID* v)
{
    // fprintf(trace, "#eof\n");
    OutFile << "#eof" << endl;
    OutFile.close();
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    // PIN_ERROR("This Pintool prints a trace of memory addresses\n" + KNOB_BASE::StringKnobSummary() + "\n");
    cerr << "Prints inst, inst addr and load value for mem loads" << endl;
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
