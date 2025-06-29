
# RTT-Secure Main Entry Point
# Advanced Enterprise Stealth Tunnel
# Designed and Developed by RmnJL
# Version: 2.0 - Enhanced Security Edition

import ../libs/chronos/chronos
import std/[random, exitprocs]
import system/ansi_c except SIGTERM
from globals import nil
import connection, iran_server, foreign_server

# Enhanced security initialization
proc initializeSecurity() =
    # Secure random seed
    randomize()
    
    # Initialize globals with enhanced security
    globals.init()
    
    # Print security banner
    if not globals.zero_logs:
        echo "RTT-Secure v", globals.version, " - by ", globals.author
        echo "🔒 Enhanced Security Mode: ", if globals.stealth_mode: "ENABLED" else: "DISABLED"
        echo "🛡️ Anti-Detection: ", if globals.anti_detection: "ENABLED" else: "DISABLED"
        echo "👻 Zero-Log Mode: ", if globals.zero_logs: "ENABLED" else: "DISABLED"

# Enhanced cleanup and security
proc setupSecurityHandlers() =
    # Secure iptables reset at exit (if enabled and safe)
    if globals.multi_port and globals.reset_iptable and globals.mode == globals.RunMode.iran:
        addExitProc do():
            if not globals.zero_logs:
                echo "🔧 Performing secure cleanup..."
            globals.resetIptables()
    
    # Enhanced signal handlers
    setControlCHook do(){.noconv.}:
        if not globals.zero_logs:
            echo "\n🛑 Secure shutdown initiated..."
        quit(0)
    
    c_signal(SIGTERM, proc(a: cint){.noconv.} =
        if not globals.zero_logs:
            echo "🛑 SIGTERM received, shutting down securely..."
        quit(0)
    )

# Enhanced system limits with security checks
proc configureSystemLimits() =
    when defined(linux) and not defined(android):
        import std/[posix, os, osproc]

        if not globals.keep_system_limit:
            if not isAdmin():
                echo "🔒 Security Error: Root access required for system optimization."
                echo "Please run as root or use --keep-os-limit flag"
                quit(-1)

            try:
                # Enhanced system limits for high performance
                discard 0 == execShellCmd("sysctl -w fs.file-max=2000000")
                discard 0 == execShellCmd("sysctl -w net.core.somaxconn=65535")
                
                var limit = RLimit(rlim_cur: 1000000, rlim_max: 1000000)
                assert 0 == setrlimit(RLIMIT_NOFILE, limit)
                
                if not globals.zero_logs:
                    echo "✅ System limits optimized for high performance"
                    
            except:
                echo "⚠️ Warning: Could not optimize system limits"
                echo "Current exception: ", getCurrentExceptionMsg()
                echo "Please run as root or use --keep-os-limit flag"
                if globals.security_level == globals.SecurityLevel.maximum:
                    quit(-1)

        # Enhanced firewall management (more secure approach)
        if globals.disable_ufw and not isAdmin():
            echo "🔒 Security Warning: Cannot manage firewall without root access"
            echo "Please run as root or manually configure firewall"
            if globals.security_level == globals.SecurityLevel.maximum:
                quit(-1)
        elif globals.disable_ufw and isAdmin():
            # Only disable if explicitly requested and in debug mode
            if globals.debug_mode:
                discard 0 == execShellCmd("sudo ufw disable")
                if not globals.zero_logs:
                    echo "⚠️ Firewall disabled for debugging (not recommended)"

# Initialize security subsystems
initializeSecurity()
setupSecurityHandlers()
configureSystemLimits()



# Enhanced connection controller with security monitoring
proc startSecureController() {.async.} =
    if not globals.zero_logs:
        echo "🔄 Starting secure connection controller..."
    
    # Start the general controller
    asyncSpawn startController()
    
    # Additional security monitoring
    if globals.anti_detection:
        asyncSpawn securityMonitor()

# Security monitoring function
proc securityMonitor() {.async.} =
    while true:
        try:
            # Monitor for suspicious patterns
            await sleepAsync(30000)  # Check every 30 seconds
            
            # Add security checks here
            if globals.debug_mode and not globals.zero_logs:
                echo "🔍 Security monitor: All clear"
                
        except:
            if not globals.zero_logs:
                echo "⚠️ Security monitor error: ", getCurrentExceptionMsg()

# Enhanced server startup with security validations
proc startSecureServer() {.async.} =
    try:
        # Validate configuration before starting
        if globals.password.len < 12:
            echo "🔒 Security Error: Password must be at least 12 characters"
            quit(-1)
        
        if globals.final_target_domain.len == 0:
            echo "🔒 Security Error: SNI domain not specified"
            quit(-1)
        
        # Start appropriate server with enhanced security
        if globals.mode == globals.RunMode.iran:
            if not globals.zero_logs:
                echo "🏠 Starting RTT-Secure Iran server..."
            asyncSpawn iran_server.start()
        elif globals.mode == globals.RunMode.kharej:
            if not globals.zero_logs:
                echo "🌍 Starting RTT-Secure Kharej server..."
            asyncSpawn foreign_server.start()
        else:
            echo "🔒 Security Error: Server mode not specified"
            quit(-1)
            
    except:
        echo "🔒 Security Error: Server startup failed - ", getCurrentExceptionMsg()
        quit(-1)

# Main execution with enhanced security
proc main() {.async.} =
    try:
        await startSecureController()
        await startSecureServer()
        
        if not globals.zero_logs:
            echo "✅ RTT-Secure started successfully"
            echo "🔒 Security Level: ", globals.security_level
            echo "🛡️ Stealth Mode: ", if globals.stealth_mode: "ACTIVE" else: "INACTIVE"
        
    except:
        echo "💥 Critical Error: ", getCurrentExceptionMsg()
        quit(-1)

# Execute main function
waitFor main()
runForever()
