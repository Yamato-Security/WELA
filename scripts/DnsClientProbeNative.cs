// One fixed DNS query, with an explicit IPv4 resolver and no configuration writes.
using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
namespace Wela.DnsClientProbe {
 public sealed class Answer { public string Name, Address; public ushort Type; public uint Flags; }
 public sealed class Result { public uint Status, ResultStatus; public ulong Options; public string QueryName, Resolver; public Answer[] Answers; }
 public static class Native {
  public const string SourceSha256="__WELA_DNS_CLIENT_SOURCE_SHA256__";
  // TCP, no recursion; bypass cache/local-name/hosts/NetBT/multicast/suffixes/IDN.
  public const ulong Options=0x002019ee;
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Request {
   public uint Version; [MarshalAs(UnmanagedType.LPWStr)] public string Name; public ushort Type;
   public ulong Options; public IntPtr Servers; public uint Interface; public IntPtr Callback,Context;
  }
  [StructLayout(LayoutKind.Sequential)] struct QueryResult { public uint Version,Status; public ulong Options; public IntPtr Records,Reserved; }
  [StructLayout(LayoutKind.Sequential)] struct Record { public IntPtr Next,Name; public ushort Type,Length; public uint Flags,Ttl,Reserved; }
  // DnsQueryEx is the documented exact export; do not allow a W-suffixed name probe.
  [DllImport("dnsapi.dll",EntryPoint="DnsQueryEx",ExactSpelling=true)] static extern uint DnsQueryEx(ref Request request,ref QueryResult result,IntPtr cancel);
  [DllImport("dnsapi.dll")] static extern void DnsRecordListFree(IntPtr records,int freeType);
  public static string ValidateResolver(string resolver) {
   if(resolver==null||!Regex.IsMatch(resolver,@"^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$"))throw new ArgumentException("One canonical dotted-decimal IPv4 resolver is required.");
   IPAddress address;if(!IPAddress.TryParse(resolver,out address)||address.AddressFamily!=System.Net.Sockets.AddressFamily.InterNetwork||address.ToString()!=resolver)throw new ArgumentException("Invalid IPv4 resolver.");
   byte[] bytes=address.GetAddressBytes();if(bytes[0]==0||bytes[0]>=224||resolver=="255.255.255.255")throw new ArgumentException("Unspecified, multicast and reserved/broadcast resolver addresses are refused.");
   return resolver;
  }
  public static Result Query(string name,string resolver) {
   if(IntPtr.Size!=8)throw new InvalidOperationException("Native 64-bit process required.");
   if(name==null||!Regex.IsMatch(name,@"^wela-[a-f0-9]{32}\.wela\.test\.\z"))throw new ArgumentException("Only the fixed random probe name is accepted.");
   ValidateResolver(resolver);
   // SDK DNS_ADDR_ARRAY header32 + one DNS_ADDR64; sockaddr_in in its first16 bytes.
   // Match Microsoft Windows-classic-samples/DNSAsyncQuery CreateDnsServerList:
   // one address, unspecified aggregate family, sockaddr IPv4 with default DNS port.
   byte[] server=new byte[96];BitConverter.GetBytes((uint)1).CopyTo(server,0);BitConverter.GetBytes((uint)1).CopyTo(server,4);
   BitConverter.GetBytes((ushort)2).CopyTo(server,32);
   IPAddress.Parse(resolver).GetAddressBytes().CopyTo(server,36);
   IntPtr servers=Marshal.AllocHGlobal(server.Length);QueryResult result=new QueryResult {Version=1};
   try {
    Marshal.Copy(server,0,servers,server.Length);
    Request request=new Request {Version=1,Name=name,Type=1,Options=Options,Servers=servers};
    uint status=DnsQueryEx(ref request,ref result,IntPtr.Zero);
    if(status==9506)throw new InvalidOperationException("Unexpected asynchronous query response.");
    List<Answer> answers=new List<Answer>();HashSet<IntPtr> seen=new HashSet<IntPtr>();IntPtr current=result.Records;
    while(current!=IntPtr.Zero) {
     if(!seen.Add(current)||seen.Count>64)throw new InvalidOperationException("DNS result record bound exceeded.");
     Record record=(Record)Marshal.PtrToStructure(current,typeof(Record));
     string recordName=Marshal.PtrToStringUni(record.Name);if(recordName==null||recordName.Length>255)throw new InvalidOperationException("Invalid DNS result name.");
     // Only A data is interpreted. Unexpected answer aliases/types cannot establish a fixed A result.
     if((record.Flags&3)==1) {
      if(record.Type!=1||!String.Equals(recordName.TrimEnd('.'),name.TrimEnd('.'),StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("Unexpected DNS answer name/type; no follow-up application connection is made.");
      if(record.Length<4)throw new InvalidOperationException("Truncated DNS A result.");
      byte[] address=new byte[4];Marshal.Copy(IntPtr.Add(current,Marshal.SizeOf(typeof(Record))),address,0,4);
      answers.Add(new Answer {Name=recordName,Type=record.Type,Flags=record.Flags,Address=new IPAddress(address).ToString()});
      if(answers.Count>16)throw new InvalidOperationException("DNS A answer bound exceeded.");
     }
     current=record.Next;
    }
    if((status==0 && answers.Count==0) || (status!=0 && answers.Count!=0))throw new InvalidOperationException("DNS status and A answers disagree.");
    return new Result {Status=status,ResultStatus=result.Status,Options=request.Options,QueryName=name,Resolver=resolver,Answers=answers.ToArray()};
   }finally{if(result.Records!=IntPtr.Zero)DnsRecordListFree(result.Records,1);Marshal.FreeHGlobal(servers);}
  }
 }
}
