# Verifies that a shared library exports exactly the C ABI declared in its
# public headers: every function marked with MACRO, and nothing else.
#
#   cmake -DLIB=<library> -DMODE=dumpbin|nm -DTOOL=<dumpbin or nm>
#         -DHEADERS=<header;...> -DMACRO=SG_CLIENT_API -P check_exports.cmake
#
# Windows: `dumpbin /exports` (or `llvm-readobj --coff-exports`) on the DLL.
# ELF: `nm -D --defined-only`.

foreach(var LIB MODE TOOL HEADERS MACRO)
    if(NOT DEFINED ${var})
        message(FATAL_ERROR "check_exports.cmake: ${var} not set")
    endif()
endforeach()

# ---- expected: functions declared with MACRO ... SG_CALL <name>(
set(expected "")
foreach(header IN LISTS HEADERS)
    file(READ "${header}" text)
    string(REGEX MATCHALL "${MACRO}[^;(]*SG_CALL[ \t\r\n]+SG_[A-Za-z0-9_]+[ \t]*\\(" decls "${text}")
    foreach(decl IN LISTS decls)
        string(REGEX MATCH "SG_[A-Za-z0-9_]+[ \t]*\\($" name "${decl}")
        string(REGEX REPLACE "[ \t]*\\($" "" name "${name}")
        list(APPEND expected "${name}")
    endforeach()
endforeach()
list(REMOVE_DUPLICATES expected)
list(LENGTH expected expected_count)
if(expected_count EQUAL 0)
    message(FATAL_ERROR "no ${MACRO} declarations found in ${HEADERS}")
endif()

# ---- actual exports
if(MODE STREQUAL "dumpbin")
    execute_process(COMMAND "${TOOL}" /nologo /exports "${LIB}"
                    OUTPUT_VARIABLE out ERROR_VARIABLE err RESULT_VARIABLE rc)
elseif(MODE STREQUAL "nm")
    execute_process(COMMAND "${TOOL}" -D --defined-only "${LIB}"
                    OUTPUT_VARIABLE out ERROR_VARIABLE err RESULT_VARIABLE rc)
elseif(MODE STREQUAL "readobj")
    execute_process(COMMAND "${TOOL}" --coff-exports "${LIB}"
                    OUTPUT_VARIABLE out ERROR_VARIABLE err RESULT_VARIABLE rc)
else()
    message(FATAL_ERROR "check_exports.cmake: unknown MODE ${MODE}")
endif()
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "${TOOL} failed (${rc}): ${err}")
endif()

string(REPLACE "\r" "" out "${out}")
string(REPLACE "\n" ";" lines "${out}")
set(actual "")
set(unexpected "")
foreach(line IN LISTS lines)
    if(MODE STREQUAL "dumpbin")
        if(line MATCHES "\\[NONAME\\]")
            list(APPEND unexpected "[NONAME] export: ${line}")
        elseif(line MATCHES "\\(forwarded to ")
            list(APPEND unexpected "forwarded export: ${line}")
        elseif(line MATCHES "^ +[0-9]+ +[0-9A-Fa-f]+ +[0-9A-Fa-f]+ +([^ ]+)")
            list(APPEND actual "${CMAKE_MATCH_1}")
        endif()
    elseif(MODE STREQUAL "readobj")
        # "  Name: <name>" inside "Export { ... }"; a forwarder has "ForwardedTo:".
        if(line MATCHES "^ +ForwardedTo:")
            list(APPEND unexpected "forwarded export: ${line}")
        elseif(line MATCHES "^ +Name: *$")
            list(APPEND unexpected "unnamed export")
        elseif(line MATCHES "^ +Name: +([^ ]+)")
            list(APPEND actual "${CMAKE_MATCH_1}")
        endif()
    else()
        # "<address> <type> <name>[@version]"; version definitions (type A) are not symbols.
        if(line MATCHES "^[0-9A-Fa-f]* *([A-Za-z]) +([^ @]+)")
            if(NOT CMAKE_MATCH_1 STREQUAL "A")
                list(APPEND actual "${CMAKE_MATCH_2}")
            endif()
        endif()
    endif()
endforeach()

foreach(name IN LISTS actual)
    if(NOT name IN_LIST expected)
        list(APPEND unexpected "${name}")
    endif()
endforeach()
set(missing "")
foreach(name IN LISTS expected)
    if(NOT name IN_LIST actual)
        list(APPEND missing "${name}")
    endif()
endforeach()

if(unexpected OR missing)
    list(JOIN unexpected "\n  " shown_unexpected)
    list(JOIN missing "\n  " shown_missing)
    message(FATAL_ERROR "${LIB} does not export exactly its C ABI.\n"
                        "Unexpected exports:\n  ${shown_unexpected}\nMissing exports:\n  ${shown_missing}")
endif()
list(LENGTH actual actual_count)
message(STATUS "${LIB}: exports exactly the ${actual_count} functions declared with ${MACRO}")
