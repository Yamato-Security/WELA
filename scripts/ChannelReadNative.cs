using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace Wela.ChannelRead {
    public static class Token {
        [StructLayout(LayoutKind.Sequential)] public struct Luid {
            public UInt32 Low; public Int32 High;
            public override string ToString() { return ((UInt32)High).ToString("x8") + Low.ToString("x8"); }
        }
        [StructLayout(LayoutKind.Sequential)] public struct Statistics {
            public Luid TokenId, AuthenticationId;
            public Int64 ExpirationTime;
            public Int32 TokenType, ImpersonationLevel;
            public UInt32 DynamicCharged, DynamicAvailable, GroupCount, PrivilegeCount;
            public Luid ModifiedId;
        }
        [DllImport("advapi32.dll", SetLastError=true)]
        private static extern bool GetTokenInformation(IntPtr token, int informationClass, out Statistics information, int size, out int returned);
        public static Statistics Read(IntPtr token) {
            Statistics value; int returned;
            int size = Marshal.SizeOf(typeof(Statistics));
            if (!GetTokenInformation(token, 10, out value, size, out returned)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (returned != size || value.TokenType != 1) throw new InvalidOperationException("Expected complete primary-token statistics.");
            return value;
        }
    }
}
