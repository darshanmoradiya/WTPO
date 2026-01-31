# Port Knowledge Database
# Contains risk ratings and human-readable explanations for known ports

$script:PortKnowledgeBase = @{
    # Critical Risk Ports (Windows Services)
    135 = @{
        Name = "RPC Endpoint Mapper"
        Service = "RpcSs"
        Risk = "Critical"
        Purpose = "Windows RPC - Required for DCOM and remote management"
        Recommendation = "Cannot disable without breaking Windows. Restrict with firewall to internal network only."
        Category = "Windows Native"
        CommonProcess = "svchost.exe"
    }
    139 = @{
        Name = "NetBIOS Session Service"
        Service = "NetBT"
        Risk = "Critical"
        Purpose = "Legacy Windows networking - Often used with SMB"
        Recommendation = "Disable if not using legacy Windows networking. Block at firewall."
        Category = "Windows Native"
        CommonProcess = "System"
    }
    445 = @{
        Name = "SMB (Server Message Block)"
        Service = "LanmanServer"
        Risk = "Critical"
        Purpose = "Windows file and printer sharing protocol"
        Recommendation = "Disable if file sharing not needed. Frequently targeted by ransomware (WannaCry, NotPetya)."
        Category = "Windows Native"
        CommonProcess = "System"
    }
    3389 = @{
        Name = "Remote Desktop Protocol (RDP)"
        Service = "TermService"
        Risk = "High"
        Purpose = "Remote desktop access to Windows machines"
        Recommendation = "Enable Network Level Authentication. Use VPN or tunneling. Monitor for brute-force attempts."
        Category = "Windows Native"
        CommonProcess = "svchost.exe"
    }
    5985 = @{
        Name = "WinRM HTTP"
        Service = "WinRM"
        Risk = "High"
        Purpose = "Windows Remote Management (PowerShell remoting)"
        Recommendation = "Use HTTPS (5986) instead. Restrict to internal network."
        Category = "Windows Native"
        CommonProcess = "svchost.exe"
    }
    5986 = @{
        Name = "WinRM HTTPS"
        Service = "WinRM"
        Risk = "Medium"
        Purpose = "Secure Windows Remote Management"
        Recommendation = "Ensure certificate validation. Restrict to internal network."
        Category = "Windows Native"
        CommonProcess = "svchost.exe"
    }
    
    # Moderate Risk Ports
    22 = @{
        Name = "SSH (Secure Shell)"
        Service = "sshd/OpenSSH"
        Risk = "Medium"
        Purpose = "Secure remote command-line access"
        Recommendation = "Use key-based authentication. Monitor for brute-force. Consider non-standard port."
        Category = "Third-Party"
        CommonProcess = "sshd.exe"
    }
    21 = @{
        Name = "FTP (File Transfer Protocol)"
        Service = "ftpd"
        Risk = "High"
        Purpose = "Unencrypted file transfer"
        Recommendation = "Replace with SFTP/FTPS. Credentials sent in cleartext."
        Category = "Third-Party"
        CommonProcess = "ftpd.exe"
    }
    23 = @{
        Name = "Telnet"
        Service = "telnet"
        Risk = "Critical"
        Purpose = "Unencrypted remote terminal access"
        Recommendation = "NEVER use in production. Replace with SSH immediately."
        Category = "Legacy"
        CommonProcess = "tlntsvr.exe"
    }
    25 = @{
        Name = "SMTP (Email)"
        Service = "SMTP"
        Risk = "Medium"
        Purpose = "Email transmission protocol"
        Recommendation = "Ensure authentication required. Monitor for relay abuse."
        Category = "Third-Party"
        CommonProcess = "smtpsvc.exe"
    }
    80 = @{
        Name = "HTTP"
        Service = "W3SVC/IIS"
        Risk = "Medium"
        Purpose = "Unencrypted web traffic"
        Recommendation = "Redirect to HTTPS. Enable TLS encryption."
        Category = "Web Service"
        CommonProcess = "w3wp.exe"
    }
    443 = @{
        Name = "HTTPS"
        Service = "W3SVC/IIS"
        Risk = "Low"
        Purpose = "Encrypted web traffic"
        Recommendation = "Ensure TLS 1.2+. Check certificate validity regularly."
        Category = "Web Service"
        CommonProcess = "w3wp.exe"
    }
    8080 = @{
        Name = "HTTP Alternate"
        Service = "Various"
        Risk = "Medium"
        Purpose = "Common development/proxy port"
        Recommendation = "Use HTTPS. Often used by Java apps and proxies."
        Category = "Web Service"
        CommonProcess = "java.exe"
    }
    8443 = @{
        Name = "HTTPS Alternate"
        Service = "Various"
        Risk = "Low"
        Purpose = "Alternative HTTPS port for web services"
        Recommendation = "Ensure TLS 1.2+. Common for management interfaces."
        Category = "Web Service"
        CommonProcess = "java.exe"
    }
    
    # Database Ports
    1433 = @{
        Name = "Microsoft SQL Server"
        Service = "MSSQLSERVER"
        Risk = "Medium"
        Purpose = "Database server connectivity"
        Recommendation = "Bind to localhost only if possible. Use Windows Authentication. Enable TLS."
        Category = "Database"
        CommonProcess = "sqlservr.exe"
    }
    3306 = @{
        Name = "MySQL/MariaDB"
        Service = "MySQL"
        Risk = "Medium"
        Purpose = "MySQL database connections"
        Recommendation = "Bind to localhost. Use strong passwords. Update regularly."
        Category = "Database"
        CommonProcess = "mysqld.exe"
    }
    5432 = @{
        Name = "PostgreSQL"
        Service = "PostgreSQL"
        Risk = "Medium"
        Purpose = "PostgreSQL database connections"
        Recommendation = "Configure pg_hba.conf properly. Bind to localhost for local apps."
        Category = "Database"
        CommonProcess = "postgres.exe"
    }
    27017 = @{
        Name = "MongoDB"
        Service = "MongoDB"
        Risk = "High"
        Purpose = "MongoDB database server"
        Recommendation = "Enable authentication. Bind to localhost. Patch regularly (history of vulnerabilities)."
        Category = "Database"
        CommonProcess = "mongod.exe"
    }
    6379 = @{
        Name = "Redis"
        Service = "Redis"
        Risk = "High"
        Purpose = "In-memory data structure store"
        Recommendation = "Bind to localhost only. Set requirepass. No default authentication."
        Category = "Database"
        CommonProcess = "redis-server.exe"
    }
    
    # Windows Core Services
    53 = @{
        Name = "DNS"
        Service = "DNS"
        Risk = "Medium"
        Purpose = "Domain Name System resolution"
        Recommendation = "Restrict queries to internal network. Monitor for DNS tunneling."
        Category = "Windows Native"
        CommonProcess = "dns.exe"
    }
    88 = @{
        Name = "Kerberos"
        Service = "KDC"
        Risk = "Low"
        Purpose = "Windows domain authentication"
        Recommendation = "Required for Active Directory. Restrict to domain controllers."
        Category = "Windows Native"
        CommonProcess = "lsass.exe"
    }
    389 = @{
        Name = "LDAP"
        Service = "NTDS"
        Risk = "Medium"
        Purpose = "Lightweight Directory Access Protocol"
        Recommendation = "Use LDAPS (636) instead. Required for Active Directory."
        Category = "Windows Native"
        CommonProcess = "lsass.exe"
    }
    636 = @{
        Name = "LDAPS (Secure LDAP)"
        Service = "NTDS"
        Risk = "Low"
        Purpose = "Encrypted directory access"
        Recommendation = "Preferred over LDAP 389. Ensure certificate validity."
        Category = "Windows Native"
        CommonProcess = "lsass.exe"
    }
    
    # Common Development Ports
    3000 = @{
        Name = "Node.js/React Dev Server"
        Service = "Development"
        Risk = "Low"
        Purpose = "Common development framework port"
        Recommendation = "Should only be open during development. Not for production."
        Category = "Development"
        CommonProcess = "node.exe"
    }
    4200 = @{
        Name = "Angular Dev Server"
        Service = "Development"
        Risk = "Low"
        Purpose = "Angular CLI development server"
        Recommendation = "Development only. Close when not actively developing."
        Category = "Development"
        CommonProcess = "node.exe"
    }
    5000 = @{
        Name = "Flask/ASP.NET Dev"
        Service = "Development"
        Risk = "Low"
        Purpose = "Common development framework port"
        Recommendation = "Development only. Not hardened for production."
        Category = "Development"
        CommonProcess = "python.exe"
    }
    9090 = @{
        Name = "Prometheus/Dev Tools"
        Service = "Monitoring"
        Risk = "Low"
        Purpose = "Metrics monitoring or development"
        Recommendation = "Restrict access. May expose system metrics."
        Category = "Monitoring"
        CommonProcess = "prometheus.exe"
    }
}

function Get-PortKnowledge {
    param([int]$Port)
    
    if ($script:PortKnowledgeBase.ContainsKey($Port)) {
        return $script:PortKnowledgeBase[$Port]
    }
    
    # Unknown port - provide generic assessment
    return @{
        Name = "Unknown Service"
        Service = "N/A"
        Risk = if ($Port -lt 1024) { "Medium" } else { "Unknown" }
        Purpose = "Custom or non-standard service"
        Recommendation = "Investigate the owning process. Verify legitimacy."
        Category = "Custom/Unknown"
        CommonProcess = "N/A"
    }
}

function Get-RiskLevel {
    param([string]$RiskRating)
    
    $riskLevels = @{
        "Critical" = 4
        "High" = 3
        "Medium" = 2
        "Low" = 1
        "Unknown" = 0
    }
    
    return $riskLevels[$RiskRating]
}

Export-ModuleMember -Function Get-PortKnowledge, Get-RiskLevel
