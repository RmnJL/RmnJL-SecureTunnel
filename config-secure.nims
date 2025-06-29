# RTT-Secure Build Configuration
# Advanced Security and Performance Settings
# Designed and Developed by RmnJL

import std/[strformat, macros, strutils, ospaths]

const Release = true
const SecureMode = true
const ProjectName = "RTT-Secure"
const Version = "2.0"
const Author = "RmnJL"

const libs_dir = "libs"
const output_dir = "dist"
const src_dir = "src"
const nimble_path = libs_dir & "/nimble"

# Enhanced security build settings
when Release:
    switch("opt", "speed")
    switch("gc", "orc")  # Latest garbage collector for better performance
    switch("define", "ssl")
    switch("define", "secure")
    switch("define", "release")
    switch("stackTrace", "off")
    switch("lineTrace", "off") 
    switch("debugger", "off")
    switch("checks", "off")
    switch("assertions", "off")
    switch("hints", "off")
    switch("warnings", "off")
else:
    switch("opt", "size")
    switch("gc", "orc")
    switch("define", "ssl")
    switch("define", "debug")
    switch("stackTrace", "on")
    switch("lineTrace", "on")

# Security hardening flags
when defined(linux):
    switch("passL", "-Wl,-z,relro,-z,now")      # Full RELRO
    switch("passL", "-Wl,-z,noexecstack")       # No executable stack
    switch("passL", "-pie")                     # Position Independent Executable
    switch("passC", "-fstack-protector-strong") # Stack protection
    switch("passC", "-D_FORTIFY_SOURCE=2")      # Buffer overflow protection
    switch("passC", "-fPIC")                    # Position Independent Code

when defined(windows):
    switch("define", "mingw")
    switch("passL", "-Wl,--dynamicbase")        # ASLR support
    switch("passL", "-Wl,--nxcompat")           # DEP support

# Performance optimizations
switch("mm", "orc")
switch("threads", "on") 
switch("tlsEmulation", "off")
switch("define", "chronicles_line_numbers")

# Output configuration
switch("out", output_dir & "/" & ProjectName)
switch("nimcache", ".nimcache")

# Include paths
switch("path", libs_dir)
switch("path", src_dir)

# Custom tasks
task build, "Build RTT-Secure":
    echo "Building RTT-Secure v" & Version & " by " & Author
    exec "nim c " & src_dir & "/main.nim"

task release, "Build optimized release":
    echo "Building RTT-Secure v" & Version & " (Release Mode)"
    exec "nim c -d:release " & src_dir & "/main.nim"

task secure, "Build with maximum security":
    echo "Building RTT-Secure v" & Version & " (Maximum Security Mode)"
    exec "nim c -d:release -d:secure -d:ssl --opt:speed " & src_dir & "/main.nim"

task clean, "Clean build artifacts":
    echo "Cleaning build artifacts..."
    rmDir(".nimcache")
    rmDir(output_dir)

task install, "Install RTT-Secure":
    echo "Installing RTT-Secure..."
    mkDir("/opt/rtt-secure")
    cpFile(output_dir & "/" & ProjectName, "/opt/rtt-secure/" & ProjectName)
    chmod("/opt/rtt-secure/" & ProjectName, 0o750)

# Enhanced nimble integration
putEnv("NIMBLE_DIR", nimble_path)
switch("nimblePath", nimble_path)

# Project metadata
hint("Project", "RTT-Secure v" & Version)
hint("Author", Author)
hint("Description", "Advanced Enterprise Stealth Tunnel")
hint("Security", "Enhanced with anti-detection and stealth capabilities")
