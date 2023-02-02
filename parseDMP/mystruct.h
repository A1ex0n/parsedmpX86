#pragma once
#include "all.h"

typedef NTSTATUS (* PMY_M_C_FUNC) (int argc, wchar_t * args[]);
typedef NTSTATUS (* PMY_M_C_FUNC_INIT) ();

typedef struct _MY_M_C {
	const PMY_M_C_FUNC pCommand;
	const wchar_t * command;
	const wchar_t * description;
} MY_M_C, *PMY_M_C;

typedef struct _MY_M {
	const wchar_t * shortName;
	const wchar_t * fullName;
	const wchar_t * description;
	const unsigned short nbCommands;
	const MY_M_C * commands;
	const PMY_M_C_FUNC_INIT pInit;
	const PMY_M_C_FUNC_INIT pClean;
} MY_M, *PMY_M;
