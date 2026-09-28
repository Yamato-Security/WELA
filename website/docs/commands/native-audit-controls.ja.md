# ネイティブ監査制御と前提条件

WELA のネイティブプロファイルは、従来の `configure` ポリシー一覧に加えて、
以下の監査サブカテゴリに対応します。情報源別プロファイルはそれぞれ独自の
成功／失敗マスクを保持し、プロファイルを選択しても全ガイドの設定を一律に
組み合わせることはありません。

| サブカテゴリ | WELA の対象 | レビュー済みのその他の要件 |
| --- | --- | --- |
| Group Membership | 成功 | Microsoft SCT、CIS v4、ASD native は成功。CIS は最小要件として指定。 |
| Application Group Management | 成功および失敗 | CIS v4 17.2.1 は両方を指定。 |
| Authorization Policy Change | 成功 | CIS v4 と Server 2025 SCT は成功、Microsoft WEF Appendix A は両方を指定。 |
| MPSSVC Rule-Level Policy Change | 成功および失敗 | Microsoft SCT、CIS v4、Microsoft WEF は両方を指定。 |
| IPsec Driver | 成功および失敗 | CIS v4 と Microsoft の一般監査ガイダンスは両方を指定。 |
| Kernel Object | 成功および失敗 | ASD native は両方を指定。対応するオブジェクト SACL とアクセス動作は別の前提条件。 |

マスクはポリシー設定を表すものであり、すべての操作で成功と失敗の両イベントが
生成されることを保証しません。イベント生成は Windows のバージョン、役割、
オブジェクトへのアクセス、実際の操作に依存します。Application Group Management
イベントはアプリケーショングループを使用する場合だけ該当します。Group Membership
イベントはログオン時のグループ情報を提供しますが、Security Group Management
イベントの代替ではありません。IPsec Driver 監査は IPsec を有効化せず、接続
セキュリティ規則も定義しません。

Kernel Object 監査を有効にしても、すべてのオブジェクトに対応する監査 ACE は
作成されません。この依存関係は計画に記録され、`auditpol` 設定が有効という理由
だけでルールを検証済みとして数えてはいけません。既存の `configure-sacl` は選択した
ファイル／レジストリ対象を扱いますが、任意のカーネルオブジェクトや AD ディレクトリ
オブジェクトは対象外です。

適用前に `plan` で選択したプロファイルと情報源を確認してください。計画では、
完全一致と最小マスク、情報源が未設定のままにする項目、選択した役割／ビルドに
適用されない制御を区別します。成功または失敗の最小要件では、もう一方の有効な
監査ビットを保持します。詳細監査プロファイルは Sysmon をインストールせず、
ファイアウォールの強制設定も変更しません。

## 情報源のバージョン

- [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319): Windows 11 24H2/25H2 および Windows Server 2022/2025 v2602 パッケージ。
- [Microsoft の監査推奨事項](https://learn.microsoft.com/ja-jp/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations)。
- [Microsoft WEF Appendix A](https://learn.microsoft.com/ja-jp/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection)。
- [ASD Windows event logging and forwarding](https://www.cyber.gov.au/business-government/detecting-responding-to-threats/event-logging/windows-event-logging-and-forwarding): 2021 年公開、ネイティブフォールバック。
- CIS Windows 11 Enterprise と Windows Server 2022 **v4.0.0**: レビュー済みの過去版ベンチマークであり、現在の CIS 要件を示すものではありません。プロファイルデータにコントロール番号と情報源リンクを記録しています。

テストではポリシーマスク、情報源別プロファイルの差異、オブジェクト監査の依存関係を
確認します。実際のイベント生成や検知範囲を証明するものではないため、対象となる
Windows の役割上で代表的な無害イベントを使って検証してください。
