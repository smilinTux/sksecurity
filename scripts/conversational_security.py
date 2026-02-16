#!/usr/bin/env python3
"""
SKSecurity Enterprise - Conversational Security Interface
The first AI-first security platform that responds to natural language
"""

import sys
import os
from pathlib import Path

# Add the conversational handler to the path
sys.path.append(str(Path(__file__).parent.parent))

try:
    from conversational_handler import ConversationalSecurityHandler
except ImportError:
    # Try alternative import path
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from conversational_handler import ConversationalSecurityHandler

def main():
    """Main entry point for conversational security"""
    handler = ConversationalSecurityHandler()
    
    # Get user input from command line or default message
    if len(sys.argv) > 1:
        user_message = ' '.join(sys.argv[1:])
    else:
        user_message = "install security scanner"
    
    print(f"👤 User Request: {user_message}")
    print("🤖 SKSecurity Enterprise:", end="\n\n")
    
    # Process the conversational request
    response = handler.handle_message(user_message)
    
    if response:
        print(response)
    else:
        print("""🛡️ **SKSecurity Enterprise - AI-First Security**

I can help you secure your AI agents with conversational commands:

🚀 **Getting Started:**
• "Install security scanner" 
• "Scan for vulnerabilities"
• "Check security status"

🔍 **Security Analysis:**
• "Scan my code for threats"
• "Run security audit" 
• "Find security risks"

🔧 **AI-Powered Solutions:**
• "Fix security issues"
• "Explain vulnerabilities"
• "Update threat intelligence"

**Try saying one of these commands!** 💪✨""")

if __name__ == "__main__":
    main()