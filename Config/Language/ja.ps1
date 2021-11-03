<#
language config:Japanese version
#>

# NTLM-Operational-Usage
$NTLM_output_8001_Log_Analysis = "8001（外向けのNTLM認証）のログ解析:"
$NTLM_output_8001_Outgoing_NTLM_Servers = "以下のサーバにNTLM認証を行っている："
$NTLM_output_8001_Outgoing_NTLM_Usernames = "以下のユーザ名でNTLM認証を行っている："
$NTLM_output_8002_Inbound_NTLM_Usernames = "8002（内向けのNTLM認証）のログ解析:"
$NTLM_output_Inbound_NTLM_Usernames = "以下のユーザ名でNTLM認証を行っている："
$NTLM_output_8004_Log_Analysis = "8004 (DCに対するNTLM認証)のログ解析:"
$NTLM_output_Secure_Channel_Names = "セキュアチャンネル名："
$NTLM_output_Usernames = "ユーザ名："
$NTLM_output_Workstation_Names = "端末名："
$NTLM_output_Secure_Channel_Types = "セキュアチャンネルタイプ："
$NTLM_output_Saving_File_To = "結果の保存先: "
$Output_Summary = "サマリ:"
$8001_Events = "8001のイベント:"
$8002_Events = "8002のイベント:"
$8004_Events = "8004のイベント:"

# function Create-EventIDStatistics
$Create_SecurityEventIDStatistics_CreatingStatisticsMessage = "イベントIDを集計しています。"
$Create_SecurityEventIDStatistics_TotalEventLogs = "イベントの合計:"
$Create_SecurityEventIDStatistics_FileSize = "ファイルサイズ:"
$Create_SecurityEventIDStatistics_FirstEvent = "最初のイベント:"
$Create_SecurityEventIDStatistics_LastEvent = "最後のイベント:"
$Create_SecurityEventIDStatistics_ProcessingTime = "処理時間：{0}時{1}分{2}秒"
$Create_SecurityEventIDStatistics_Count = "カウント"
$Create_SecurityEventIDStatistics_ID = "ID"
$Create_SecurityEventIDStatistics_Event = "イベント"
$Create_SecurityEventIDStatistics_TimelineOutput = "タイムライン出力"
$Create_SecurityEventIDStatistics_Comment = "コメント"

$Detect_ProcessingDetectionMessage = "ルールベースでの検知中です。`n"

$1100 = @{
    EventTitle = 'イベントログサービスがシャットダウンした';
    Comment    = 'Good for finding signs of anti-forensics but most likely false positives when the system shuts down.';
}

$1101 = @{
    EventTitle = '監査イベントがトランスポートによって削除された';
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
    EventTitle = '認証パッケージがローカル セキュリティ機関によって読み込まれた';
}

$4611 = @{
    EventTitle = '信頼されたログオン プロセスがローカルセキュリティ機関で登録された';
}

$4614 = @{
    EventTitle = 'セキュリティ アカウント マネージャによって通知パッケージが読み込まれた';
}

$4616 = @{
    EventTitle = 'システム時刻の変更';
}

$4622 = @{
    EventTitle = 'セキュリティ パッケージがローカル セキュリティ機関によって読み込まれた';
}

$4624 = @{
    EventTitle     = 'アカウントログオン';
    TimelineDetect = "Yes";
}
$4625 = @{
    EventTitle     = 'ログオンに失敗';
    TimelineDetect = "Yes"; 
}
$4627 = @{
    EventTitle = 'グループメンバーシップ情報';
}

$4634 = @{
    EventTitle     = 'ログオフ';
    TimelineDetect = "Yes"
}

$4647 = @{
    EventTitle     = 'ログオフ';
    TimelineDetect = "Yes" 
}

$4648 = @{
    EventTitle     = '明示的なログオン';
    TimelineDetect = "Yes"
}
$4672 = @{
    EventTitle     = '管理者ログオン';
    TimelineDetect = "Yes";
}
$4673 = @{
    EventTitle = '特権のあるサービスが呼び出された';
}
$4674 = @{
    EventTitle = '特権のあるオブジェクトに対して操作が行われた';
}
$4688 = @{
    EventTitle = '新しいプロセスが起動された';
}
$4696 = @{
    EventTitle = 'プライマリートークンがプロセスに割り当てられた';
}
$4692 = @{
    EventTitle = 'データ保護用のマスターキーのバックアップが行われた';
}
$4697 = @{
    EventTitle = 'サービスがインストールされた';
}
$4717 = @{
    EventTitle = 'システムセキュリティのアクセス権がアカウントに付与された';
}
$4719 = @{
    EventTitle = 'システム監査ポリシーが変更された';
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
    EventTitle = '空のパスワードでアカウントの照会を行った';
}
      
$4798 = @{
    EventTitle = 'ユーザーのローカルグループメンバシップが列挙された';
}
    
$4799 = @{
    EventTitle = 'ローカルグループのメンバーシップを列挙した';
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
    EventTitle = 'ブート構成データを読み込んだ';
}
    
$4902 = @{
    EventTitle = 'ユーザごとの監査ポリシーテーブルが作成された';
}
     
$4904 = @{
    EventTitle = 'セキュリティイベントソースの登録を行った';
}
    
$4905 = @{
    EventTitle = 'セキュリティイベントソースの登録を解除した';
}
     
$4907 = @{
    EventTitle = 'オブジェクトの監査設定が変更された';
}
     
$4944 = @{
    EventTitle = 'ファイアウォール起動時に有効なポリシー';
}
    
$4945 = @{
    EventTitle = 'Rule listed when the firewall started' ;
    Comment    = "ファイアウォールが起動する際に大量のログが発生するのでフィルタした方が良い";
}

$4946 = @{
    EventTitle = 'ファイアウォールの例外リストにルールが追加された';
}
    
$4947 = @{
    EventTitle = 'ファイアウォールの例外リストのルールが変更された';
}
    
$4948 = @{
    EventTitle = 'ファイアウォールの例外リストのルールが削除された';
}
    
$4954 = @{
    EventTitle = 'ファイアウォールグループに新しい設定が適用された';
}
    
$4956 = @{
    EventTitle = 'ファイアウォールのアクティブプロファイルが変更された';
}

$4985 = @{
    EventTitle = 'トランザクションの状態が変わった';
}

$5024 = @{
    EventTitle = 'ファイアウォールが起動された';
}

$5033 = @{
    EventTitle = 'ファイアウォールドライバが起動された';
}
     
$5038 = @{
    EventTitle = 'コードの整合性により、ファイルの画像ハッシュが無効であると判断された';
}
    
$5058 = @{
    EventTitle = 'キーファイルの操作';
}
     
$5059 = @{
    EventTitle = 'キーの移行操作';
}
    
$5061 = @{
    EventTitle = '暗号化操作';
}
     
$5140 = @{
    EventTitle = 'ネットワーク共有オブジェクトへのアクセスがあった';
}
    
$5142 = @{
    EventTitle = 'ネットワーク共有オブジェクトが追加された';
}
    
$5144 = @{
    EventTitle = 'ネットワーク共有オブジェクトが削除された';
}
    
$5379 = @{
    EventTitle = 'クレデンシャルマネージャの認証情報が読み込まれた';
}
    
$5381 = @{
    EventTitle = 'Valutの認証情報が読み取られた';
}
    
$5382 = @{
    EventTitle = 'Valutの認証情報が読み取られた';
}
    
$5478 = @{
    EventTitle = 'IPsecサービスが起動された';
}
    
$5889 = @{
    EventTitle = 'COM+ カタログからオブジェクトが削除された';
}
    
$5890 = @{
    EventTitle = 'COM+ カタログからオブジェクトが追加された';
}
$unregistered = @{
    EventTitle = "不明";
}




# function Create-LogonTimeline
$Create_LogonTimeline_Welcome_Message = "サービスアカウント、ローカルシステム、マシンアカウント等の不要なイベントを省いて、ログオンタイムラインを作成します。"
$Create_LogonTimeline_Filename = "ファイル名 = {0}" 
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
$Create_LogonTimeline_Type0 =  "タイプ  0 システムログオン（端末の起動時間): "
$Create_LogonTimeline_Type2 =  "タイプ  2 インタラクティブログオン (例：コンソール、VNC等) (注意：認証情報がメモリに格納されて、盗まれる危険性がある。):"
$Create_LogonTimeline_Type3 =  "タイプ  3 ネットワークログオン (例：SMB共有、netコマンド、rpcclient、psexec、winrm等々):"
$Create_LogonTimeline_Type4 =  "タイプ  4 バッチログオン (例：スケジュールされたタスク):"
$Create_LogonTimeline_Type5 =  "タイプ  5 サービスログオン:"
$Create_LogonTimeline_Type7 =  "タイプ  7 ロック解除（またはRDPの再接続)のログオン:"
$Create_LogonTimeline_Type8 =  "タイプ  8 平文のネットワークログオン (例：IISのBasic認証)(注意：ハッシュ化されていないパスワードが使用されている。):"
$Create_LogonTimeline_Type9 =  "タイプ  9 新しい認証情報でのログオン (例：「runas /netonly」のコマンド)(注意：認証情報がメモリに格納されて、盗まれる危険性がある。):"
$Create_LogonTimeline_Type10 = "タイプ 10 リモートインタラクティブのログオン (例：RDP) (注意：認証情報がメモリに格納されて、盗まれる危険性がある。):"
$Create_LogonTimeline_Type11 = "タイプ 11 キャッシュされた認証情報によるインタラクティブログオン (例：DCに接続できない場合):"
$Create_LogonTimeline_Type12 = "タイプ 12 キャッシュされた認証情報によるリモートインタラクティブログオン (例：キャッシュされた認証情報によるRDP、Microsoftライブアカウントの使用):"
$Create_LogonTimeline_Type13 = "タイプ 13 キャッシュされた認証情報によるロック解除のログオン (例：DCに接続できない場合のロック解除またはRDP再接続):"
$Create_LogonTimeline_TypeOther = "その他のタイプのログオン:"
$Create_LogonTimeline_localComputer = "ローカル"
$Create_LogonTimeline_LoadingEVTX = "イベントログをロードしています。"
$Create_LogonTimeline_PleaseWait = "少々お待ち下さい。"
$Create_LogonTimeline_AnalyzingLogs = "ログを解析しています。"

$Confirm_DefConfirm_ExecutionPolicy_Bypassed = "確認:SIGMAの検知ルールを利用するために、PowerShellのExectionPolicyをBypassに設定する必要があります。実行しますか？"
$Confirm_DefConfirm_DefenderRealTimeScan_enderRealTimeScan_Disabled = ""
$Info_Noload_SIGMAMODULE = "情報:SIGMAの検知ルールの読み込みがユーザによってキャンセルされました。"
$Info_GetEventNoMatch = "情報:Get-WinEventで調査対象に合致するイベントレコードはありませんでした。"
$Warn_GetEvent = "注意:Get-WinEventでエラーが発生しました。エラーが発生したイベントレコードは読み込まれません。"
$Warn_DC_LiveAnalysis = "注意：ドメインコントローラーでライブ調査をしない方が良いです。ログをオフラインにコピーしてから解析して下さい。"
$Error_InCompatible_LiveAnalysisAndLogFile = "エラー：「-LiveAnalysis」 と「-LogFile」「-LogDirectory」を同時に指定できません。"
$Error_InCompatible_LogDirAndFile = "エラー：「-LogDirectory」 と「-LogFile」を同時に指定できません。"
$Error_NotSupport_LiveAnalysys = "エラー： ライブ調査はWindowsにしか対応していません。"
$Error_NeedAdministratorPriv = "エラー： Powershellを管理者として実行する必要があります。"
$Error_NoSaveOutputWithCSV = "エラー： 「-SaveOutput」を指定してください"
$Error_NoNeedSaveOutputWithGUI = "エラー： 「-OutputGUI」と「-SaveOutput」を同時に指定できません。"
$Error_InCompatible_NoLiveAnalysisOrLogFileSpecified = "エラー: -LiveAnalysisまたは-LogFileを指定する必要があります。"
$Error_NoEventsFound = "エラー: イベントがない！"
$Error_ThisFunctionDoesNotSupportOutputGUI = "エラー： この機能は-OutputGUIに対応していない。"
$Error_ThisFunctionDoesNotSupportOutputCSV = "エラー： この機能は-OutputCSVに対応していない。"

#Remote live analysis
$remoteAnalysis_getComputername = "リモートコンピュータのマシン名（IPアドレス or ホスト名）を入力してください "
$remoteAnalysis_getCredential = "リモートコンピュータの認証情報を入力してください。"
$Error_remoteAnalysis_InvalidExecutionPolicy = "エラー： ExecutionPolicyは「RemoteSigned」である必要があります。"
$Error_remoteAnalysis_UnregisteredComputername = "エラー： リモートコンピュータのマシン名をtrustedhostsに登録する必要があります。"
$Error_remoteAnalysis_FailedTestWSMan = "エラー： Test-WSManの実行が失敗しました。リモートコンピュータへの接続ができません。"
$Warn_remoteAnalysis_Stopped_WinRMservice = "注意： リモートコンピュータ上のWinRMサービスが停止している可能性があります。"
$Warn_remoteAnalysis_wrongRemoteComputerInfo = "注意： 間違ったマシン名または認証情報が入力された可能性があります。"

#function Show-Contributors
$Show_Contributors1 = @"


                                                        ..Jv+
                                                   ..gMHHMHMHn.
                                               ..gMHHHHHHHHHHHH
                                            .(HHHHHHHM##HHHH@@H`
                                ..     ..JgHHHHHHM#"(M##HHHHMH^
                              ,hgMHQHMHHHHH@H@M#"`.d##HHHHH@#!
                              JHHHHHHHHH@H@MB=`  .M#HHHHH@#=
                              J@HHHHHHHHHMY'   .d###HHHM#^
                              WHHHHHHMHH]     .M##HH@#=
                              ?H@H####HHMh,  J###HMY`
                               ?WHHH####]?`(dH#HMY`
                                ,@HHHN##F .M##M@`
                                 `?HH#MD J##HM=
                                       .HH#M9       .......
                                      .H###>  ..JdMHHHHHH@HHMmJ,
                                    .H##M8((kHMMHB""7?!??77TWMHHNa.
                                  .j#N####M9=`                7MHHN,
                                 .MNNN##"`                     .M#HH[
                               .d#NNN@!                         (H##M.
                              .M###Mt                           ,####[
                            .dH####^                            ,#N##]
                          .dHH##M#`                             g#NNM]
                          ?@HH#M#`                             .####H%
                          .WMHM#!                ..           .H#NN#M!
                            ?""^          .gMMHHH#H#Mm.      .H####HF
                                        .M#####HH####M:     (###N#HD
                                      .d#N###"`   MN#M)   .M#####MF
                                      d#NNN#`    JNN#@`.JMN####HM%
                                     .H#NMMb   .MNNNNM##N####HM@`
                                    .H##NMMHNNMNNMNNNNNN###HHB'
                                    ,HH#MMMNNNNMNNNNNNN##HMB'
                                    (MHNNMMMNNNM###N##HMM@!         `  `      `
                                   .JMNNMNNNMHHHHHHMMB"!     ..JgHMHHHHHHMNm+HHN,
                              ..+HHHH##MHBY""""=!`      ..gMH#H#####H##H#H#HH##N#Na,
                     .,.` ..g##HHHM#"^              ..gM#####HHHHMHMMMMMMMHHH######HMe
                  `..##N######MB"!               ..H#####HHMMHY"=!          d#N###H#HHb
                  HMH######NN#N,              ..M#NN##HMMB"`              .j###N#HH#HH#`
                .WMHH####HH#####m.          .d##NN##HMY!                .J#N###MHHM"!`
                d@H###M@=`   _TMHMe      .+##NNNN#M@^                 .JHMMHMHY"7!
                 WMMM"`        ,M##N,  .MNNNHNN#MY                  .d#"! _`
                   `            .W#N#NMNNNMNMMM=                  .Y=
                                  U#NNNNNNN#HY                  .=                               `
                                   ?NMNNN###@                 .^
                                   .MH###H###
             `                       (UH##N#M_
                                       (HMMMB`
                                                           .....(JvZTTUUUUUUUHHC?
                                                ....Jz7zzw+J+ggHHHHHHHHHHHHHHHHHNa..
                                         ...J71Ag+g#NNMHHHHHHHHHHHHHHHHHHHH@H###HHMN,
                                    ..JY4a+gMHHHHH##NNNN#HMHYYYYTUYYT"Y""""W##MHHHHHb
                               ..JY6agMMM######MMH9"HNN#HH]              .d#MHHHHHHH#
                         ``..JHNMMNNNN####MMB"^    .MMN#HHF           ..H#HH###HHHM"!
                       ..+MMMNNNNNNNNMHMHY!       .dNMN#HH%        .(H##HH#HHHHMY'
                  `..gH####NNNNNNNMMMY^    ,!    .dNNNN#H#     ..+M#H###MMMB""`
               ..+M#NNNNN#####MMM@^    .(J^     .MNMMN##B`  .JMMM#"UWB"`
            ..M##N##NNN###HM#M@^     .1J^      .#NNN#HM3.JWB"!
           .HHdM#####MHHHHHT#NN.   .dd%      .HNNNNMMQd"^
           (HHHNdMH#HHHMB!  WN#b .+HHF     .dHMMBTXY!`  ...........+gH;
           (HHHHHN?"""!     ,#NMg###%    .dM8i(+H8+JOXUVUUWkXkXHHHHHH@Na,
            WM####Me.        M#NNNMD...+HMXQMHMNHMHHMMHMMHHHHH@HHHHHHHH@N.
            .MH##HHN,        dNNNNN######HHHHHH#HHHHMMMMMMMHMHHHBHMMMMMHMD
             (MHHMHML   .(gHMN#NNNNNN###HHHMMB""7`                      !
              ?7WMB@'   H###NNNNNNNNHMMB"^`
                      .MH###N##HMNNN-                  jHb           .gm.
                     .MHHHHMB"! .#N#M[                 WNMN,        .H##N,
       ``             ?Y"=    .H##HM@`                JN#HHHR      .MN###Hb
     `                      .d###=`                 .MNN##HH@    .H#NN#MHM^
                          .dHM"                   .d#NN###MY   .HH#N#MM#=`.,
                       ..MMY'                   .J#####MMD` .JMH##NNMNggmHHMo.
                     .dH#=                     .M#####H@!..M####NNNNNNNN#HHHHMHm!
                ` .JMMY!                     .dH#N####nJMNMNNNNNNNMNNNNN##HHHHMH%
             (HNHMH#=           (MN.       .+HHNNNMMNNNMNMNNNNNNNNMMMHY""""YHHB%
           .MHH#N#a,            d#H-      .MH#HNNMMMNMNNNNNMMMBWNMb
          .HHH#NN###Nm,       .MH#Hb    .HHHHHM#NNMNMNMMMMY=`  JNNN@.
           MHH##NNNN##Mg\   .MHHHHM% .dHHH#H@#T#NNMNNMY^       (NNN@  .
           .TMMH#N#NNNMMNx(MHH@M"`   (@HHM@#= .NNNN#M`         (NNNNgMHh..
                7TWM#NNMM#HHMY'      J@HM#=   (NNMNHF    ..JgMHNNNMNNNNHHM)
                    -U##H#H"          ?T?     dNMM#M\(gMHHHH###NNMNMMN#HH#'
                   .d#MY!       ..            dNNMNM(HHH####HHH#NNNMMBWMF
                 .dM@^ ..JXUTTWHMHe           WNNNN#,MHHMH""! .#NNMF
              ..MB=(JWBYu+kkWkWMHH@Ma..       M#MN## ?TY    .MM#NN#\` ...+HMa..
       ... ..dMh+HHMmgMHMY"!  .#HHHMHHMR.     M#MN#F     .(M" (#NNMNMHHH##H@@M\
      JHHHMMMM#######M"'      `  ?MHHHHHN`    M#NNM]   .J=..JgMNNMNNNN#MMM#B"`
     ,HHHHH#NNNN##M#=             .TMMY"      M#NN#]..dQgM###NNNNNNNMHMB^
     ,MHHHH###NN#M^                           M#NNNLd#####MH"7MNNNM=
      ."YHMH#####N_           .+HHHHHJ.       MHNN#M#M#"=`  .JMMMH@;
           ?MHHMY! .W&..    .H#"` ?MH##Mm,    HHNNM#`    .."` dHH@@]!
              7`  ..7M@HH..HH=     .WMMMHN,  .H#M#MN   .?`    dHUMK`       ..........
                .</  (HHHHHN.        ?YY7^   .##NMMb         ....J+ggmgQQMHHHHHHHMMMNNMHHmkmQkl`
               JhK    ?HHHHMN.              .#NNMNNNgMmJggHHHHHH###HHHHHHHHHHHHHHMM#NN#HHMH@@MD
       .,    .HH#`     TMH@H@b               WMMMNMNN###H#HHH#H####HMMMHYY"YYUUUUWM#NXHgk@MMHH!
       d@p. (H##\       (HB"^                J@M##MNN###HMMMHB9UQg&yXY""7??7~```_7"BgdMYHR7C
       HHHNM###M`                            ZjWMTMMMMMHBY""""?`
       d@H###N##                                .`.=
       .MHH###MM
        ,MHHH#M@[
         ,MMMH@@P
          .4HMY'


"@



$Show_Contributors2 =
"コントリビューター:

ogino(GitHub:@oginoPmP) - 開発
DustInDark(GitHub:@hitenkoku) - ローカライゼーション、和訳
つぼっく(twitter: @ytsuboi0322) - 和訳
秀真（ほつま） - アート

コントリビュータを募集しています！
"

function Show-Help {
    
    Write-Host 
    Write-Host "Windows Event Log Analyzer(WELA) ゑ羅(ウェラ)" -ForegroundColor Green
    Write-Host "バージョン: $YEAVersion" -ForegroundColor Green
    Write-Host "作者: 田中ザック (@yamatosecurity)と大和セキュリティメンバー" -ForegroundColor Green
    Write-Host 

    Write-Host "解析ソースを一つ指定して下さい：" 
    Write-Host "   -LiveAnalysis" -NoNewline -ForegroundColor Green
    Write-Host " : ホストOSのログを解析する"

    Write-Host "   -LogFile <ログファイルのパス>" -NoNewline -ForegroundColor Green
    Write-Host " : オフラインの.evtxファイルを解析する"

    Write-Host "   -LogDirectory <ログファイルのディレクトリのパス> (未完成)" -NoNewline -ForegroundColor Green
    Write-Host " : 複数のオフラインの.evtxファイルを解析する"

    Write-Host "   -RemoteLiveAnalysis" -NoNewline -ForegroundColor Green
    Write-Host " : リモートマシンのログでタイムラインを作成する"

    Write-Host
    Write-Host "解析タイプを一つ指定して下さい:"

    Write-Host "   -AnalyzeNTLM_UsageBasic" -NoNewline -ForegroundColor Green
    Write-Host " : NTLM Operationalログを解析し、NTLM認証の使用を簡潔に出力する"

    Write-Host "   -AnalyzeNTLM_UsageDetailed" -NoNewline -ForegroundColor Green
    Write-Host " : NTLM Operationalログを解析し、NTLM認証の使用を詳細に出力する"

    Write-Host "   -SecurityEventID_Statistics" -NoNewline -ForegroundColor Green
    Write-Host " : セキュリティログのイベントIDの集計情報を出力する" 

    Write-Host "   -EasyToReadSecurityLogonTimeline" -NoNewline -ForegroundColor Green
    Write-Host " : セキュリティログからユーザログオンの読みやすいタイムラインを出力する"

    Write-Host "   -SecurityLogonTimeline" -NoNewline -ForegroundColor Green
    Write-Host " : セキュリティログからユーザログオンの簡単なタイムラインを出力する"

    Write-Host 
    Write-Host "解析オプション:"

    Write-Host "   -StartTimeline ""<YYYY-MM-DD HH:MM:SS>""" -NoNewline -ForegroundColor Green
    Write-Host " : タイムラインの始まりを指定する"

    Write-Host "   -EndTimeline ""<YYYY-MM-DD HH:MM:SS>""" -NoNewline -ForegroundColor Green
    Write-Host " : タイムラインの終わりを指定する"

    Write-Host 
    Write-Host "-SecurityLogonTimelineの解析オプション:"

    Write-Host "   -IsDC" -NoNewline -ForegroundColor Green
    Write-Host " : ドメインコントローラーのログの場合は指定して下さい"

    Write-Host "   -UseDetectRule <preset rule | path-to-ruledirectory>(Default:preset rule='0')" -NoNewline -ForegroundColor Green
    Write-Host "：検知ルールに該当するイベントの出力を行う"
    Write-Host "   preset rule| 0:None 1: DeepBlueCLI 2:SIGMA all:all-preset"


    Write-Host 
    Write-Host "出力方法（デフォルト：標準出力）:"

    Write-Host "   -SaveOutput <出力パス>" -NoNewline -ForegroundColor Green
    Write-Host " : テキストファイルに出力する"

    Write-Host "   -OutputCSV" -NoNewline -ForegroundColor Green
    Write-Host " : CSVファイルに出力する"

    Write-Host "   -OutputGUI" -NoNewline -ForegroundColor Green
    Write-Host " : Out-GridView GUIに出力する"

    Write-Host 
    Write-Host "出力オプション:"

    Write-Host "   -USDateFormat" -NoNewline -ForegroundColor Green
    Write-Host " : 日付をMM-DD-YYYY形式で出力する (デフォルト： YYYY-MM-DD)"

    Write-Host "   -EuropeDateFormat" -NoNewline -ForegroundColor Green
    Write-Host " : 日付をDD-MM-YYYY形式で出力する (デフォルト： YYYY-MM-DD)" 

    Write-Host "   -UTC" -NoNewline -ForegroundColor Green
    Write-Host " : 時間をUTC形式で出力する。（デフォルトはローカルタイムゾーン）"

    Write-Host "   -English" -NoNewline -ForegroundColor Green
    Write-Host " : 英語で出力する"

    Write-Host "   -Japanese" -NoNewline -ForegroundColor Green
    Write-Host " : 日本語で出力する"

    Write-Host 
    Write-Host "-LogonTimelineの出力オプション:"

    Write-Host "   -HideTimezone" -NoNewline -ForegroundColor Green
    Write-Host " :  タイムゾーンの表示をしない"

    Write-Host "   -ShowLogonID" -NoNewline -ForegroundColor Green
    Write-Host " : ログオンIDを出力する"
     
    Write-Host
    Write-Host "その他:"

    Write-Host "   -ShowContributors" -NoNewline -ForegroundColor Green
    Write-Host " : コントリビューターの一覧表示" 

    Write-Host "   -QuietLogo" -NoNewline -ForegroundColor Green
    Write-Host " : ロゴを表示させずに実行する" 


    Write-Host

}