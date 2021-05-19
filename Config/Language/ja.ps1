<#
language config:Japanese version
#>


# Event ID Statistics
$1100 = @{
    EventTitle = 'イベントログサービスがシャットダウンしました。';
    Comment    = 'Good for finding signs of anti-forensics but most likely false positives when the system shuts down.';
}
$1101 = @{
    EventTitle = 'Audit Events Have Been Dropped By The Transport';
}
$1102 = @{
    EventTitle     = 'イベントログがクリアされた';
    TimelineDetect = "Yes";
    Comment        = 'Should not happen normally so this is a good event to look out for.';
}
$1107 = @{
    EventTitle = 'イベント処理によるエラー';
}
$4608 = @{
    EventTitle = 'Windowsが起動された';
}
$4610 = @{
    EventTitle = 'An authentication package has been loaded by the Local Security Authority';
}
$4611 = @{
    EventTitle = 'A trusted logon process has been registered with the Local Security Authority';
}
$4614 = @{
    EventTitle = 'A notification package has been loaded by the Security Account Manager';
}
$4616 = @{
    EventTitle = 'システム時刻の変更';
}
$4622 = @{
    
    EventTitle = 'A security package has been loaded by the Local Security Authority';
}
$4624 = @{
    
    EventTitle      = 'アカウントログオン';
    TimelineDetect = "Yes";
}
$4625 = @{
    EventTitle      = 'ログオンに失敗';
    TimelineDetect = "Yes"; 
}
$4634 = @{
    EventTitle      = 'ログオフ';
    TimelineDetect = "Yes"
}
$4647 = @{
    EventTitle      = 'ログオフ';
    TimelineDetect = "Yes" 
}
$4648 = @{
    EventTitle      = '明示的なログオン';
    TimelineDetect = "Yes"
}
$4672 = @{
    EventTitle      = '管理者ログオン';
    TimelineDetect = "Yes";
}
$4688 = @{
    EventTitle = '新しいプロセスが起動された';
}
$4696 = @{
    EventTitle = 'Primary token assigned to process';
}
$4692 = @{
    EventTitle = 'Backup of data protection master key was attempted';
}
$4697 = @{
    EventTitle = 'サービスがインストールされた';
}
$4717 = @{
    EventTitle = 'System security access was granted to an account';
}
$4719 = @{
    EventTitle = 'System audit policy was changed';
}
$4720 = @{
    EventTitle     = 'ユーザアカウントが作成された';
    TimelineDetect = "Yes"
}
$4722 = @{
    EventTitle = 'ユーザアカウントが有効になった';
}
$4724 = @{
    EventTitle = 'パスワードリセット';
}
$4725 = @{
    EventTitle = 'ユーザアカウントが無効になった';
}
$4726 = @{
    EventTitle = 'ユーザアカウントが削除された';
} 
$4728 = @{
    EventTitle = 'ユーザがセキュリティグローバルグループに追加された';
}
    
$4729 = @{
    EventTitle = 'ユーザがセキュリティグローバルグループから削除された';
}
    
$4732 = @{
    EventTitle = 'ユーザがセキュリティローカルグループに追加された';
}
    
$4733 = @{
    EventTitle = 'ユーザがセキュリティローカルグループから削除された';
}
    
$4735 = @{
    EventTitle = 'セキュリティローカルグループの変更';
}
    
$4727 = @{
    EventTitle = 'セキュリティグローバルグループの変更';
}
    
$4738 = @{
    EventTitle = 'ユーザアカウントプロパティの変更';
}
    
$4739 = @{
    EventTitle = 'ドメインポリシーが変更された';
}
    
$4776 = @{
    EventTitle = 'ローカルユーザへのNTLMログオン';
}
    
$4778 = @{
    EventTitle = 'RDPセッションの再接続またはユーザーの簡易切り替えによるログオン';
}
    
$4779 = @{
    EventTitle = 'RDPセッションの切断または簡易切り替えによるログオフ';
}
    
$4797 = @{
    EventTitle = 'Attempt to query the account for a blank password';
}
      
$4798 = @{
    EventTitle = 'User''s local group membership was enumerated';
}
    
$4799 = @{
    EventTitle = 'Local group membership was enumerated';
}
     
$4781 = @{
    EventTitle = 'ユーザ名が変更された';
}
    
$4800 = @{
    EventTitle = '端末がロックされた’;
}
    
$4801 = @{
    EventTitle = '端末がロック解除された';
}
    
$4826 = @{
    EventTitle = 'Boot configuration data loaded';
}
    
$4902 = @{
    EventTitle = 'Per-user audit policy table was created';
}
     
$4904 = @{
    EventTitle = 'Attempt to register a security event source';
}
    
$4905 = @{
    EventTitle = 'Attempt to unregister a security event source';
}
     
$4907 = @{
    EventTitle = 'Auditing settings on object was changed';
}
     
$4944 = @{
    EventTitle = 'Policy active when firewall started';
}
    
$4945 = @{
    EventTitle = 'Rule listed when the firewall started' ; Comment = "ファイアウォールが起動する際に大量のログが発生するのでフィルタした方が良い" 
}
$4946 = @{
    EventTitle = 'Rule added to firewall exception list';
}
    
$4947 = @{
    EventTitle = 'Rule modified in firewall exception list';
}
    
$4948 = @{
    EventTitle = 'Rule deleted in firewall exception list';
}
    
$4954 = @{
    EventTitle = 'New setting applied to firewall group policy';
}
    
$4956 = @{
    EventTitle = 'Firewall active profile changed';
}
    
$5024 = @{
    EventTitle = 'ファイアウォールが起動された';
}
    
$5033 = @{
    EventTitle = 'ファイアウォールドライバが起動された';
}
     
$5038 = @{
    EventTitle = 'Code integrity determined that the image hash of a file is not valid';
}
    
$5058 = @{
    EventTitle = 'Key file operation';
}
     
$5059 = @{
    EventTitle = 'Key migration operation';
}
    
$5061 = @{
    EventTitle = 'Cryptographic operation';
}
     
$5140 = @{
    EventTitle = 'Network share object was accessed';
}
    
$5142 = @{
    EventTitle = 'A network share object was added';
}
    
$5144 = @{
    EventTitle = 'A network share object was deleted';
}
    
$5379 = @{
    EventTitle = 'Credential Manager credentials were read';
}
    
$5381 = @{
    EventTitle = 'Vault credentials were read';
}
    
$5382 = @{
    EventTitle = 'Vault credentials were read';
}
    
$5478 = @{
    EventTitle = 'IPsecサービスが起動された';
}
    
$5889 = @{
    EventTitle = 'An object was added to the COM+ Catalog';
}
    
$5890 = @{
    EventTitle = 'An object was added to the COM+ Catalog';
}
$unregistered = @{
    EventTitle = "不明";
}




# function Create-LogonTimeline
$Create_LogonTimeline_Welcome_Message = "サービスアカウント、ローカルシステム、マシンアカウント等の不要なイベントを省いて、ログオンタイムラインを作成します。`n少々お待ち下さい。"
$Create_LogonTimeline_Filesize = "ファイルサイズ = {0}" 
$Create_LogonTimeline_Estimated_Processing_Time = "想定処理時間：{0}時{1}分{2}秒"
$Create_LogonTimeline_ElapsedTimeOutput = "{0}日{1}時{2}分{3}秒"
$Create_LogonTimeline_Timezone = "タイムゾーン"
$Create_LogonTimeline_LogonTime = "ログオン時間"
$Create_LogonTimeline_LogoffTime = "ログオフ時間"
$Create_LogonTimeline_ElapsedTime = "経過時間"
$Create_LogonTimeline_Type = "タイプ"
$Create_LogonTimeline_TargetUser = "ターゲットユーザ"
$Create_LogonTimeline_Auth = "認証"
$Create_LogonTimeline_isAdmin = "管理者"
$Create_LogonTimeline_SourceWorkstation = "送信元のホスト名"
$Create_LogonTimeline_SourceIpAddress = "送信元のIPアドレス"
$Create_LogonTimeline_SourceIpPort = "送信元のポート番号"
$Create_LogonTimeline_LogonID = "ログオンID"
$Create_LogonTimeline_Processing_Time = "処理時間：{0}時{1}分{2}秒"
$Create_LogonTimeline_NoLogoffEvent = "ログオフイベント無し"
$Create_LogonTimeline_Total_Logon_Event_Records = "ログオンイベントの合計: "
$Create_LogonTimeline_Data_Reduction = "ログイベントのデータ削減率: "
$Create_LogonTimeline_Total_Filtered_Logons = "フィルタ済のログオンイベント: "
$Create_LogonTimeline_Type0 = "タイプ  0 システムログオン（端末の起動時間): "
$Create_LogonTimeline_Type2 = "タイプ  2 インタラクティブログオン (例：コンソール、VNC等) (注意：認証情報がメモリに格納されて、盗まれる危険性がある。):"
$Create_LogonTimeline_Type3 = "タイプ  3 ネットワークログオン (例：SMB共有、netコマンド、rpcclient、psexec、winrm等々):"
$Create_LogonTimeline_Type4 = "タイプ  4 バッチログオン (例：スケジュールされたタスク):"
$Create_LogonTimeline_Type5 = "タイプ  5 サービスログオン:"
$Create_LogonTimeline_Type7 = "タイプ  7 ロック解除（またはRDPの再接続)のログオン:"
$Create_LogonTimeline_Type8 = "タイプ  8 平文のネットワークログオン (例：IISのBasic認証)(注意：ハッシュ化されていないパスワードが使用されている。):"
$Create_LogonTimeline_Type9 = "タイプ  9 新しい認証情報でのログオン (例：「runas /netonly」のコマンド)(注意：認証情報がメモリに格納されて、盗まれる危険性がある。):"
$Create_LogonTimeline_Type10 = "タイプ 10 リモートインタラクティブのログオン (例：RDP) (注意：認証情報がメモリに格納されて、盗まれる危険性がある。):"
$Create_LogonTimeline_Type11 = "タイプ 11 キャッシュされた認証情報によるインタラクティブログオン (例：DCに接続できない場合):"
$Create_LogonTimeline_Type12 = "タイプ 12 キャッシュされた認証情報によるリモートインタラクティブログオン (例：キャッシュされた認証情報によるRDP、Microsoftライブアカウントの使用):"
$Create_LogonTimeline_Type13 = "タイプ 13 キャッシュされた認証情報によるロック解除のログオン (例：DCに接続できない場合のロック解除またはRDP再接続):"
$Create_LogonTimeline_TypeOther = "その他のタイプのログオン:"
