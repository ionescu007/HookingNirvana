        title  "Instrumentation Hook"

include ksamd64.inc

        subttl  "Function to receive Instrumentation Callbacks"

        EXTERN InstrumentationCHook:PROC

        NESTED_ENTRY InstrumentationHook, TEXT

        mov r11, rax

        GENERATE_EXCEPTION_FRAME Rbp

        mov rdx, r11
        mov rcx, r10
        call InstrumentationCHook

        RESTORE_EXCEPTION_STATE Rbp

        mov rax, r11

        jmp r10

        NESTED_END InstrumentationHook, TEXT

        subttl  "Function to receive CFG Callbacks"

        EXTERN CfgCHook:PROC

        NESTED_ENTRY CfgHook, TEXT

        GENERATE_EXCEPTION_FRAME Rbp

        call CfgCHook

        RESTORE_EXCEPTION_STATE Rbp

        ret

        NESTED_END CfgHook, TEXT

        end

