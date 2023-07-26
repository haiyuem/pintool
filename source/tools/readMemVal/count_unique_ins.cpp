/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

//
// This will print out each unique instruction (op name) and each unique reg name, with the number of apperances. 
//

#include <fstream>
#include <iostream>
#include <string.h>
#include <unordered_map>
#include "pin.H"

std::ofstream OutFile;
std::unordered_map<std::string, UINT32> _tabStr;
std::unordered_map<std::string, UINT32> _regStr;

VOID Routine(RTN rtn, VOID* rtn_name_to_parse)
{
    KNOB< std::string >* rtn_name_to_parse_ptr = (KNOB< std::string >*)rtn_name_to_parse;
    std::string rtn_name_to_parse_str = rtn_name_to_parse_ptr->Value().c_str();
    
    if ((rtn_name_to_parse_str == "") || (RTN_Name(rtn) == rtn_name_to_parse_str)){
        RTN_Open(rtn);
        
        for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
        {
            _tabStr[INS_Mnemonic(ins)] += 1;  // increment count for this instruction

            for (unsigned int i = 0; i < INS_OperandCount(ins); i++)
            {
                if (INS_OperandIsReg(ins,i))
                {
                    REG reg = INS_OperandReg(ins, i);
                    _regStr[REG_StringShort(reg)] += 1;  // increment count for this register
                }
            }
        }
        RTN_Close(rtn);
    }
}

VOID Fini(INT32 code, VOID* v)
{
    OutFile << "Unique Ins: Count" << std::endl;
    for (auto const& entry: _tabStr){
        OutFile << entry.first << ": " << entry.second << std::endl;
    }
    OutFile << "Unique Reg Names: Count" << std::endl;
    for (auto const& entry: _regStr){
        OutFile << entry.first << ": " << entry.second << std::endl;
    }
    if (OutFile.is_open())
    {
        OutFile.close();
    }
}

KNOB< std::string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "count_unique_ins.out", "specify output file name");
KNOB< std::string > rtn_name_to_parse(KNOB_MODE_WRITEONCE, "pintool", "rtn_name_to_parse", "", "Specify RTN name to parse; if none, will parse all RTNs");

int main(int argc, char* argv[])
{
    // Initialize symbol table code, needed for rtn instrumentation
    PIN_InitSymbols();
    // Initialize pin
    if (PIN_Init(argc, argv)) return -1;
    OutFile.open(KnobOutputFile.Value().c_str());
    // Register Routine to be called to instrument rtn
    RTN_AddInstrumentFunction(Routine, &rtn_name_to_parse);
    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    // Start the program, never returns
    PIN_StartProgram();
    return 0;
}
