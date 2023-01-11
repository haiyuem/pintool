/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

//
// for the first MAX_INS_COUNT load insns, the program prints out everytime it executes, and the mem addr loaded, and the value
//

#include <fstream>
#include <iomanip>
#include <iostream>
#include <string.h>
#include "pin.H"
#include <map>
#include <vector>
#include <utility> 
using std::cerr;
using std::dec;
using std::endl;
using std::hex;
using std::ofstream;
using std::setw;
using std::string;
using std::map;
using std::vector;
using std::pair;

static const int MAX_INS_COUNT = 1;
ofstream OutFile[MAX_INS_COUNT];
static string _tabStr[0x1000];
static string _tabFirstIns[0x1000];
static const int START_NUM = 8;
// movaps	-128+16(pA0), rA0

int count = 0;
struct addr_val_pair {
  ADDRINT memaddr = 0;
  UINT64 value = 0;
  ADDRINT pc = 0;
  string ins = "";
} ;
map<ADDRINT, vector<addr_val_pair>> insdatamap;
map<ADDRINT, const string> pcinsmap;
ADDRINT offset = 0;

VOID AddLoadData(ADDRINT pc, ADDRINT memaddr, const string ins)
{
    
    //if pc is already in the map, add to the list. If not (and if <30 pc), add to map
    auto entry = insdatamap.find(pc);
    UINT64 value;
    PIN_SafeCopy(&value, (VOID*)memaddr, sizeof(UINT64));
    addr_val_pair new_pair;
    
    // new_pair.memaddr = ADDRINT((unsigned long long int)memaddr-(unsigned long long int)offset);
    new_pair.memaddr = memaddr;
    new_pair.value = value;
    new_pair.pc = pc;
    new_pair.ins = ins;
    if (entry != insdatamap.end()){
        entry->second.push_back(new_pair);
        
    }else {
        count++;
        if (!((count > START_NUM) && (count <=(START_NUM+MAX_INS_COUNT)))) {
            return;
        }
        vector<addr_val_pair> v;
        v.push_back(new_pair);
        insdatamap.insert({pc, v});
        pcinsmap.insert({pc, ins});
        if (!offset){
            offset = memaddr;
        }
    }
    // OutFile1 << hex << "Ins: " << ins << endl;
}

// Pin calls this function every time a new rtn is executed
VOID Routine(RTN rtn, VOID* rtn_name_to_parse)
{
    KNOB< string >* rtn_name_to_parse_ptr = (KNOB< string >*)rtn_name_to_parse;
    string rtn_name_to_parse_str = rtn_name_to_parse_ptr->Value().c_str();
    if ((rtn_name_to_parse_str == "") || (RTN_Name(rtn) == rtn_name_to_parse_str)){
        RTN_Open(rtn);
        // OutFile << "RTN base addr: 0x" << RTN_Address(rtn) << "\t" << RTN_Name(rtn) << endl;
        for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
        {
            _tabStr[INS_Opcode(ins)] = INS_Mnemonic(ins); 
            if (INS_IsMemoryRead(ins)){
                INS_InsertCall(ins, 
                IPOINT_BEFORE,
                AFUNPTR(AddLoadData),
                IARG_INST_PTR,
                IARG_MEMORYREAD_EA, 
                //IARG_REG_VALUE,
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_END
                );
            }
     
        }

        RTN_Close(rtn);
    }

}

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "same_ins_load_pattern", "specify output file name");
KNOB< string > rtn_name_to_parse(KNOB_MODE_WRITEONCE, "pintool", "rtn_name_to_parse", "", "Specify RTN name to parse; if none, will parse all RTNs");

// This function is called when the application exits
// It prints the name and count for each procedure
VOID Fini(INT32 code, VOID* v)
{

    // OutFile << "Addr\t\tOffset\tNumber\tDisass" << endl;
    // for (UINT32 i = 0; i < 1000; i++){
    //     if (_tabInsCount[i])
    //     OutFile << hex << _tabInsAddr[i] << "\t" << i << "\t" << dec << _tabInsCount[i] << "\t" << _tabStr[i] << endl;
    // }
    // for (UINT32 i = 0; i < 1000; i++){
    //     if (!_tabStr[i].empty())
    //     OutFile << _tabStr[i] << "\t" << _tabFirstIns[i] << endl;
    // }
    int count=0;
    for ( auto it = insdatamap.begin(); it != insdatamap.end(); ++it  ){
        OutFile[count] << hex << "PC: " << it->first <<endl;
        OutFile[count] << hex << " Ins: " << pcinsmap.find(it->first)->second << "\tBase Mem Load Addr: " << offset << endl;
        vector<addr_val_pair> vec = it->second;
        for ( auto it_vec = vec.begin(); it_vec != vec.end(); ++it_vec  ){
            // addr_val_pair pair = it_vec
            OutFile[count] << hex << "memaddr: " << (it_vec->memaddr-offset) << "\tval: " << it_vec->value << endl;
        }
        count++;
    }
    // OutFile << "#eof" << endl;
    for (int i=0; i<MAX_INS_COUNT; ++i){
        if (OutFile[i].is_open()) {OutFile[i].close();}
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
    for (int i=0; i<MAX_INS_COUNT; ++i){
        string file = (string)(KnobOutputFile.Value().c_str())+"_"+std::to_string(i)+".out";
        OutFile[i].open(file);
    }
    

    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    // Register Routine to be called to instrument rtn
    RTN_AddInstrumentFunction(Routine, &rtn_name_to_parse);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
