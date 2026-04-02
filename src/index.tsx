import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { serveStatic } from 'hono/cloudflare-workers'

const app = new Hono()

// CORS設定
app.use('/api/*', cors())

// 静的ファイルの提供
app.use('/static/*', serveStatic({ root: './' }))

// =============================
// 官公需API プロキシエンドポイント
// =============================

// 入札案件検索API
app.get('/api/search', async (c) => {
  const query = c.req.query('query') || ''
  const projectName = c.req.query('projectName') || ''
  const orgName = c.req.query('orgName') || ''
  const count = c.req.query('count') || '20'
  const lgCode = c.req.query('lgCode') || ''
  const category = c.req.query('category') || ''
  const procedureType = c.req.query('procedureType') || ''
  const certification = c.req.query('certification') || ''
  const cftIssueDate = c.req.query('cftIssueDate') || ''
  const tenderDeadline = c.req.query('tenderDeadline') || ''
  const openingDate = c.req.query('openingDate') || ''
  const startIndex = c.req.query('startIndex') || '1'

  // 官公需APIのパラメータ構築
  const params = new URLSearchParams()

  // Query、Project_Name、Organization_Name、LG_Codeのいずれか1つは必須
  if (query) {
    params.set('Query', query)
  } else if (projectName) {
    params.set('Query', projectName)
    params.set('Project_Name', projectName)
  } else if (orgName) {
    params.set('Query', orgName)
    params.set('Organization_Name', orgName)
  } else if (lgCode) {
    params.set('Query', ' ')
    params.set('LG_Code', lgCode)
  } else {
    // デフォルト: 最新の全案件
    params.set('Query', '入札')
  }

  if (projectName && query) params.set('Project_Name', projectName)
  if (orgName && query) params.set('Organization_Name', orgName)
  if (lgCode && query) params.set('LG_Code', lgCode)
  if (category) params.set('Category', category)
  if (procedureType) params.set('Procedure_Type', procedureType)
  if (certification) params.set('Certification', certification)
  if (cftIssueDate) params.set('CFT_Issue_Date', cftIssueDate)
  if (tenderDeadline) params.set('Tender_Submission_Deadline', tenderDeadline)
  if (openingDate) params.set('Opening_Tenders_Event', openingDate)
  params.set('Count', count)

  const apiUrl = `http://www.kkj.go.jp/api/?${params.toString()}`

  try {
    const response = await fetch(apiUrl, {
      headers: {
        'User-Agent': 'BidSearchApp/1.0',
      },
    })

    if (!response.ok) {
      return c.json({ error: 'APIリクエストに失敗しました', status: response.status }, 500)
    }

    const xmlText = await response.text()
    const parsed = parseKkjXml(xmlText)

    return c.json(parsed)
  } catch (error) {
    console.error('API Error:', error)
    return c.json({ error: 'APIの取得に失敗しました', details: String(error) }, 500)
  }
})

// 統計情報取得API (ダッシュボード用)
app.get('/api/stats', async (c) => {
  try {
    // 本日の新着案件取得
    const today = new Date()
    const yesterday = new Date(today)
    yesterday.setDate(yesterday.getDate() - 7)
    const dateFrom = formatDate(yesterday)

    const categories = ['1', '2', '3']
    const categoryNames: Record<string, string> = { '1': '物品', '2': '工事', '3': '役務' }
    const statsPromises = categories.map(async (cat) => {
      const params = new URLSearchParams({
        Query: '入札',
        Category: cat,
        CFT_Issue_Date: `${dateFrom}/`,
        Count: '1',
      })
      const res = await fetch(`http://www.kkj.go.jp/api/?${params.toString()}`)
      const xml = await res.text()
      const parsed = parseKkjXml(xml)
      return {
        category: categoryNames[cat],
        count: parsed.totalHits || 0,
      }
    })

    const categoryStats = await Promise.all(statsPromises)

    // 最新案件取得
    const latestParams = new URLSearchParams({
      Query: '入札',
      Count: '5',
      CFT_Issue_Date: `${dateFrom}/`,
    })
    const latestRes = await fetch(`http://www.kkj.go.jp/api/?${latestParams.toString()}`)
    const latestXml = await latestRes.text()
    const latestParsed = parseKkjXml(latestXml)

    return c.json({
      categoryStats,
      latestItems: latestParsed.items?.slice(0, 5) || [],
      lastUpdated: new Date().toISOString(),
    })
  } catch (error) {
    return c.json({ error: 'Stats取得に失敗しました' }, 500)
  }
})

// =============================
// XML パーサー
// =============================

// CDATAセクションを除去するヘルパー
function cleanCdata(str: string): string {
  return str.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').trim()
}

function parseKkjXml(xmlText: string): { totalHits: number; items: any[]; error?: string } {
  try {
    // エラーチェック
    const errorMatch = xmlText.match(/<Error>(.*?)<\/Error>/)
    if (errorMatch) {
      return { totalHits: 0, items: [], error: errorMatch[1] }
    }

    // SearchHits取得
    const hitsMatch = xmlText.match(/<SearchHits>(\d+)<\/SearchHits>/)
    const totalHits = hitsMatch ? parseInt(hitsMatch[1]) : 0

    // SearchResult取得
    const items: any[] = []
    const resultRegex = /<SearchResult>([\s\S]*?)<\/SearchResult>/g
    let match

    while ((match = resultRegex.exec(xmlText)) !== null) {
      const block = match[1]
      const item: any = {}

      const fields: Record<string, string> = {
        ResultId: 'resultId',
        Key: 'key',
        ExternalDocumentURI: 'url',
        ProjectName: 'projectName',
        Date: 'date',
        FileType: 'fileType',
        LgCode: 'lgCode',
        PrefectureName: 'prefectureName',
        CityCode: 'cityCode',
        CityName: 'cityName',
        OrganizationName: 'organizationName',
        Certification: 'certification',
        CftIssueDate: 'cftIssueDate',
        PeriodEndTime: 'periodEndTime',
        Category: 'category',
        ProcedureType: 'procedureType',
        Location: 'location',
        TenderSubmissionDeadline: 'tenderSubmissionDeadline',
        OpeningTendersEvent: 'openingTendersEvent',
        ItemCode: 'itemCode',
        ProjectDescription: 'projectDescription',
      }

      for (const [tag, key] of Object.entries(fields)) {
        const fieldMatch = block.match(new RegExp(`<${tag}>(.*?)<\/${tag}>`, 's'))
        if (fieldMatch) {
          // CDATAセクションをクリーニング
          item[key] = cleanCdata(fieldMatch[1].trim())
        }
      }

      // 添付ファイル
      const attachments: any[] = []
      const attachRegex = /<Attachment>([\s\S]*?)<\/Attachment>/g
      let attachMatch
      while ((attachMatch = attachRegex.exec(block)) !== null) {
        const attachBlock = attachMatch[1]
        const nameMatch = attachBlock.match(/<Name>(.*?)<\/Name>/)
        const uriMatch = attachBlock.match(/<Uri>(.*?)<\/Uri>/)
        if (nameMatch && uriMatch) {
          attachments.push({
            name: cleanCdata(nameMatch[1]),
            uri: cleanCdata(uriMatch[1])
          })
        }
      }
      item.attachments = attachments

      items.push(item)
    }

    return { totalHits, items }
  } catch (e) {
    return { totalHits: 0, items: [], error: String(e) }
  }
}

function formatDate(date: Date): string {
  const y = date.getFullYear()
  const m = String(date.getMonth() + 1).padStart(2, '0')
  const d = String(date.getDate()).padStart(2, '0')
  return `${y}-${m}-${d}`
}

// =============================
// フロントエンド HTML配信
// =============================
app.get('/', (c) => {
  return c.html(renderHTML())
})

app.get('*', (c) => {
  return c.html(renderHTML())
})

function renderHTML(): string {
  return `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>入札DX - 入札案件情報検索</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.4.0/css/all.min.css">
  <script src="https://cdn.jsdelivr.net/npm/axios@1.6.0/dist/axios.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Noto+Sans+JP:wght@300;400;500;700&display=swap');
    * { font-family: 'Noto Sans JP', sans-serif; }
    .gradient-bg { background: linear-gradient(135deg, #1e3a5f 0%, #2563eb 100%); }
    .card-hover { transition: all 0.2s ease; }
    .card-hover:hover { transform: translateY(-2px); box-shadow: 0 10px 25px rgba(0,0,0,0.15); }
    .badge-物品 { background: #dbeafe; color: #1d4ed8; }
    .badge-工事 { background: #d1fae5; color: #065f46; }
    .badge-役務 { background: #fef3c7; color: #92400e; }
    .badge-default { background: #f3f4f6; color: #374151; }
    .loading-spinner { border: 3px solid #f3f3f3; border-top: 3px solid #2563eb; border-radius: 50%; width: 32px; height: 32px; animation: spin 0.8s linear infinite; }
    @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    .sidebar-link { transition: all 0.15s; }
    .sidebar-link:hover, .sidebar-link.active { background: rgba(255,255,255,0.15); border-left: 3px solid white; }
    .sidebar-link { border-left: 3px solid transparent; }
    .modal-overlay { background: rgba(0,0,0,0.5); backdrop-filter: blur(4px); }
    .slide-in { animation: slideIn 0.3s ease; }
    @keyframes slideIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
    .tag { display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 500; }
    ::-webkit-scrollbar { width: 6px; }
    ::-webkit-scrollbar-track { background: #f1f5f9; }
    ::-webkit-scrollbar-thumb { background: #94a3b8; border-radius: 3px; }
    .btn-primary { background: linear-gradient(135deg, #2563eb, #1d4ed8); transition: all 0.2s; }
    .btn-primary:hover { background: linear-gradient(135deg, #1d4ed8, #1e40af); transform: translateY(-1px); }
    .result-row { transition: background 0.15s; }
    .result-row:hover { background: #f0f9ff; }
  </style>
</head>
<body class="bg-gray-50 min-h-screen">

<!-- サイドバー -->
<div id="sidebar" class="fixed left-0 top-0 h-full w-64 gradient-bg text-white z-30 flex flex-col shadow-2xl">
  <div class="p-6 border-b border-white/20">
    <div class="flex items-center gap-3">
      <div class="w-10 h-10 bg-white/20 rounded-xl flex items-center justify-center">
        <i class="fas fa-gavel text-white text-lg"></i>
      </div>
      <div>
        <h1 class="text-lg font-bold">入札DX</h1>
        <p class="text-xs text-blue-200">官公需情報検索</p>
      </div>
    </div>
  </div>
  <nav class="flex-1 p-4 space-y-1">
    <a href="#" onclick="showPage('dashboard')" class="sidebar-link active flex items-center gap-3 px-4 py-3 rounded-lg text-sm" id="nav-dashboard">
      <i class="fas fa-th-large w-4"></i> ダッシュボード
    </a>
    <a href="#" onclick="showPage('search')" class="sidebar-link flex items-center gap-3 px-4 py-3 rounded-lg text-sm" id="nav-search">
      <i class="fas fa-search w-4"></i> 案件検索
    </a>
    <a href="#" onclick="showPage('new')" class="sidebar-link flex items-center gap-3 px-4 py-3 rounded-lg text-sm" id="nav-new">
      <i class="fas fa-clock w-4"></i> 新着案件
    </a>
    <a href="#" onclick="showPage('construction')" class="sidebar-link flex items-center gap-3 px-4 py-3 rounded-lg text-sm" id="nav-construction">
      <i class="fas fa-hard-hat w-4"></i> 工事案件
    </a>
    <a href="#" onclick="showPage('goods')" class="sidebar-link flex items-center gap-3 px-4 py-3 rounded-lg text-sm" id="nav-goods">
      <i class="fas fa-box w-4"></i> 物品案件
    </a>
    <a href="#" onclick="showPage('service')" class="sidebar-link flex items-center gap-3 px-4 py-3 rounded-lg text-sm" id="nav-service">
      <i class="fas fa-concierge-bell w-4"></i> 役務案件
    </a>
  </nav>
  <div class="p-4 border-t border-white/20">
    <p class="text-xs text-blue-200 text-center">データ提供: 官公需情報ポータルサイト</p>
    <p class="text-xs text-blue-300 text-center mt-1">中小企業庁</p>
  </div>
</div>

<!-- メインコンテンツ -->
<div class="ml-64 min-h-screen">

  <!-- ヘッダー -->
  <header class="bg-white border-b border-gray-200 px-8 py-4 sticky top-0 z-20 shadow-sm">
    <div class="flex items-center justify-between">
      <div>
        <h2 id="page-title" class="text-xl font-bold text-gray-800">ダッシュボード</h2>
        <p class="text-xs text-gray-500 mt-0.5">官公需情報ポータルサイト (kkj.go.jp) のリアルタイムデータ</p>
      </div>
      <div class="flex items-center gap-4">
        <span id="last-updated" class="text-xs text-gray-400"></span>
        <div class="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
        <span class="text-xs text-gray-500">APIリアルタイム連携中</span>
      </div>
    </div>
  </header>

  <!-- ページコンテンツ -->
  <main class="p-8">

    <!-- ダッシュボード -->
    <div id="page-dashboard" class="page-content">
      <div id="stats-loading" class="flex justify-center items-center py-16">
        <div class="text-center">
          <div class="loading-spinner mx-auto mb-4"></div>
          <p class="text-gray-500 text-sm">データ取得中...</p>
        </div>
      </div>
      <div id="stats-content" class="hidden">
        <!-- 統計カード -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <div class="bg-white rounded-2xl p-6 shadow-sm border border-gray-100 card-hover">
            <div class="flex items-center justify-between mb-3">
              <div class="w-12 h-12 bg-blue-100 rounded-xl flex items-center justify-center">
                <i class="fas fa-file-alt text-blue-600 text-xl"></i>
              </div>
              <span class="text-xs bg-blue-50 text-blue-600 px-2 py-1 rounded-full">7日間</span>
            </div>
            <div class="text-3xl font-bold text-gray-800 mb-1" id="stat-total">-</div>
            <div class="text-sm text-gray-500">全案件数</div>
          </div>
          <div class="bg-white rounded-2xl p-6 shadow-sm border border-gray-100 card-hover">
            <div class="flex items-center justify-between mb-3">
              <div class="w-12 h-12 bg-green-100 rounded-xl flex items-center justify-center">
                <i class="fas fa-hard-hat text-green-600 text-xl"></i>
              </div>
              <span class="text-xs bg-green-50 text-green-600 px-2 py-1 rounded-full">工事</span>
            </div>
            <div class="text-3xl font-bold text-gray-800 mb-1" id="stat-construction">-</div>
            <div class="text-sm text-gray-500">工事案件</div>
          </div>
          <div class="bg-white rounded-2xl p-6 shadow-sm border border-gray-100 card-hover">
            <div class="flex items-center justify-between mb-3">
              <div class="w-12 h-12 bg-purple-100 rounded-xl flex items-center justify-center">
                <i class="fas fa-box text-purple-600 text-xl"></i>
              </div>
              <span class="text-xs bg-purple-50 text-purple-600 px-2 py-1 rounded-full">物品</span>
            </div>
            <div class="text-3xl font-bold text-gray-800 mb-1" id="stat-goods">-</div>
            <div class="text-sm text-gray-500">物品案件</div>
          </div>
          <div class="bg-white rounded-2xl p-6 shadow-sm border border-gray-100 card-hover">
            <div class="flex items-center justify-between mb-3">
              <div class="w-12 h-12 bg-orange-100 rounded-xl flex items-center justify-center">
                <i class="fas fa-concierge-bell text-orange-600 text-xl"></i>
              </div>
              <span class="text-xs bg-orange-50 text-orange-600 px-2 py-1 rounded-full">役務</span>
            </div>
            <div class="text-3xl font-bold text-gray-800 mb-1" id="stat-service">-</div>
            <div class="text-sm text-gray-500">役務案件</div>
          </div>
        </div>

        <!-- 最新案件 -->
        <div class="bg-white rounded-2xl shadow-sm border border-gray-100 mb-8">
          <div class="p-6 border-b border-gray-100 flex items-center justify-between">
            <h3 class="text-base font-bold text-gray-800 flex items-center gap-2">
              <i class="fas fa-bolt text-yellow-500"></i> 直近の新着案件
            </h3>
            <button onclick="showPage('new')" class="text-sm text-blue-600 hover:text-blue-800 font-medium">
              すべて表示 <i class="fas fa-arrow-right ml-1"></i>
            </button>
          </div>
          <div id="latest-items" class="divide-y divide-gray-50"></div>
        </div>

        <!-- クイック検索 -->
        <div class="bg-gradient-to-br from-blue-50 to-indigo-50 rounded-2xl p-8 border border-blue-100">
          <h3 class="text-lg font-bold text-gray-800 mb-2 flex items-center gap-2">
            <i class="fas fa-search text-blue-600"></i> クイック検索
          </h3>
          <p class="text-sm text-gray-600 mb-6">キーワードを入力して案件を検索できます</p>
          <div class="flex gap-3">
            <input
              id="quick-search"
              type="text"
              placeholder="例：システム開発、清掃、警備..."
              class="flex-1 px-4 py-3 border border-blue-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-300 bg-white text-sm"
              onkeypress="if(event.key==='Enter') doQuickSearch()"
            >
            <button onclick="doQuickSearch()" class="btn-primary text-white px-8 py-3 rounded-xl font-medium text-sm shadow-md">
              <i class="fas fa-search mr-2"></i>検索
            </button>
          </div>
          <div class="mt-4 flex flex-wrap gap-2">
            <span class="text-xs text-gray-500 mr-2">よく検索されるキーワード：</span>
            <button onclick="quickSearchTag('システム')" class="text-xs bg-white border border-blue-200 text-blue-600 px-3 py-1 rounded-full hover:bg-blue-50">システム</button>
            <button onclick="quickSearchTag('清掃')" class="text-xs bg-white border border-blue-200 text-blue-600 px-3 py-1 rounded-full hover:bg-blue-50">清掃</button>
            <button onclick="quickSearchTag('警備')" class="text-xs bg-white border border-blue-200 text-blue-600 px-3 py-1 rounded-full hover:bg-blue-50">警備</button>
            <button onclick="quickSearchTag('設計')" class="text-xs bg-white border border-blue-200 text-blue-600 px-3 py-1 rounded-full hover:bg-blue-50">設計</button>
            <button onclick="quickSearchTag('保守')" class="text-xs bg-white border border-blue-200 text-blue-600 px-3 py-1 rounded-full hover:bg-blue-50">保守</button>
            <button onclick="quickSearchTag('調査')" class="text-xs bg-white border border-blue-200 text-blue-600 px-3 py-1 rounded-full hover:bg-blue-50">調査</button>
          </div>
        </div>
      </div>
    </div>

    <!-- 案件検索ページ -->
    <div id="page-search" class="page-content hidden">
      <!-- 検索フォーム -->
      <div class="bg-white rounded-2xl shadow-sm border border-gray-100 p-6 mb-6">
        <h3 class="text-base font-bold text-gray-800 mb-4 flex items-center gap-2">
          <i class="fas fa-sliders-h text-blue-600"></i> 詳細検索
        </h3>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          <div>
            <label class="block text-xs font-medium text-gray-600 mb-1">キーワード</label>
            <input id="s-query" type="text" placeholder="案件名・内容で検索..." class="w-full px-3 py-2.5 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-300">
          </div>
          <div>
            <label class="block text-xs font-medium text-gray-600 mb-1">機関名</label>
            <input id="s-orgname" type="text" placeholder="例：国土交通省、東京都..." class="w-full px-3 py-2.5 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-300">
          </div>
          <div>
            <label class="block text-xs font-medium text-gray-600 mb-1">都道府県</label>
            <select id="s-lgcode" class="w-full px-3 py-2.5 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-300">
              <option value="">全国</option>
              <option value="01">北海道</option><option value="02">青森県</option><option value="03">岩手県</option>
              <option value="04">宮城県</option><option value="05">秋田県</option><option value="06">山形県</option>
              <option value="07">福島県</option><option value="08">茨城県</option><option value="09">栃木県</option>
              <option value="10">群馬県</option><option value="11">埼玉県</option><option value="12">千葉県</option>
              <option value="13">東京都</option><option value="14">神奈川県</option><option value="15">新潟県</option>
              <option value="16">富山県</option><option value="17">石川県</option><option value="18">福井県</option>
              <option value="19">山梨県</option><option value="20">長野県</option><option value="21">岐阜県</option>
              <option value="22">静岡県</option><option value="23">愛知県</option><option value="24">三重県</option>
              <option value="25">滋賀県</option><option value="26">京都府</option><option value="27">大阪府</option>
              <option value="28">兵庫県</option><option value="29">奈良県</option><option value="30">和歌山県</option>
              <option value="31">鳥取県</option><option value="32">島根県</option><option value="33">岡山県</option>
              <option value="34">広島県</option><option value="35">山口県</option><option value="36">徳島県</option>
              <option value="37">香川県</option><option value="38">愛媛県</option><option value="39">高知県</option>
              <option value="40">福岡県</option><option value="41">佐賀県</option><option value="42">長崎県</option>
              <option value="43">熊本県</option><option value="44">大分県</option><option value="45">宮崎県</option>
              <option value="46">鹿児島県</option><option value="47">沖縄県</option>
            </select>
          </div>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-4">
          <div>
            <label class="block text-xs font-medium text-gray-600 mb-1">カテゴリー</label>
            <select id="s-category" class="w-full px-3 py-2.5 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-300">
              <option value="">すべて</option>
              <option value="1">物品</option>
              <option value="2">工事</option>
              <option value="3">役務</option>
            </select>
          </div>
          <div>
            <label class="block text-xs font-medium text-gray-600 mb-1">公示種別</label>
            <select id="s-procedure" class="w-full px-3 py-2.5 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-300">
              <option value="">すべて</option>
              <option value="1">一般競争入札</option>
              <option value="2">簡易公募型競争入札</option>
              <option value="3">指名競争入札</option>
            </select>
          </div>
          <div>
            <label class="block text-xs font-medium text-gray-600 mb-1">公告日（開始）</label>
            <input id="s-date-from" type="date" class="w-full px-3 py-2.5 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-300">
          </div>
          <div>
            <label class="block text-xs font-medium text-gray-600 mb-1">公告日（終了）</label>
            <input id="s-date-to" type="date" class="w-full px-3 py-2.5 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-300">
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button onclick="doSearch()" class="btn-primary text-white px-8 py-2.5 rounded-xl font-medium text-sm shadow-md flex items-center gap-2">
            <i class="fas fa-search"></i> 検索する
          </button>
          <button onclick="clearSearch()" class="text-gray-500 hover:text-gray-700 px-4 py-2.5 border border-gray-200 rounded-xl text-sm hover:bg-gray-50">
            <i class="fas fa-times mr-1"></i> クリア
          </button>
          <select id="s-count" class="ml-auto px-3 py-2.5 border border-gray-200 rounded-lg text-sm">
            <option value="20">20件表示</option>
            <option value="50">50件表示</option>
            <option value="100">100件表示</option>
          </select>
        </div>
      </div>

      <!-- 検索結果 -->
      <div id="search-result-area"></div>
    </div>

    <!-- 新着/工事/物品/役務 ページ -->
    <div id="page-new" class="page-content hidden">
      <div id="new-result-area"></div>
    </div>
    <div id="page-construction" class="page-content hidden">
      <div id="construction-result-area"></div>
    </div>
    <div id="page-goods" class="page-content hidden">
      <div id="goods-result-area"></div>
    </div>
    <div id="page-service" class="page-content hidden">
      <div id="service-result-area"></div>
    </div>

  </main>
</div>

<!-- 案件詳細モーダル -->
<div id="modal" class="fixed inset-0 z-50 hidden flex items-center justify-center modal-overlay p-4">
  <div class="bg-white rounded-2xl shadow-2xl max-w-3xl w-full max-h-[90vh] overflow-y-auto slide-in">
    <div class="sticky top-0 bg-white border-b border-gray-100 px-6 py-4 flex items-center justify-between rounded-t-2xl">
      <h3 class="text-base font-bold text-gray-800" id="modal-title">案件詳細</h3>
      <button onclick="closeModal()" class="w-8 h-8 flex items-center justify-center rounded-full hover:bg-gray-100 text-gray-400">
        <i class="fas fa-times"></i>
      </button>
    </div>
    <div id="modal-content" class="p-6"></div>
  </div>
</div>

<script>
// ========================
// グローバル状態
// ========================
let currentPage = 'dashboard';
let searchResults = [];

// ========================
// ページ遷移
// ========================
function showPage(page) {
  document.querySelectorAll('.page-content').forEach(el => el.classList.add('hidden'));
  document.querySelectorAll('.sidebar-link').forEach(el => el.classList.remove('active'));

  document.getElementById('page-' + page).classList.remove('hidden');
  document.getElementById('nav-' + page).classList.add('active');
  currentPage = page;

  const titles = {
    dashboard: 'ダッシュボード',
    search: '案件検索',
    new: '新着案件',
    construction: '工事案件',
    goods: '物品案件',
    service: '役務案件'
  };
  document.getElementById('page-title').textContent = titles[page] || page;

  // ページ固有の初期化
  if (page === 'dashboard') {
    loadDashboard();
  } else if (page === 'new') {
    loadCategoryPage('new', null, '新着案件');
  } else if (page === 'construction') {
    loadCategoryPage('construction', '2', '工事案件');
  } else if (page === 'goods') {
    loadCategoryPage('goods', '1', '物品案件');
  } else if (page === 'service') {
    loadCategoryPage('service', '3', '役務案件');
  }
}

// ========================
// ダッシュボード
// ========================
async function loadDashboard() {
  try {
    document.getElementById('stats-loading').classList.remove('hidden');
    document.getElementById('stats-content').classList.add('hidden');

    const res = await axios.get('/api/stats');
    const data = res.data;

    // 統計表示
    const stats = data.categoryStats || [];
    let total = 0;
    stats.forEach(s => {
      total += s.count;
      if (s.category === '工事') document.getElementById('stat-construction').textContent = s.count.toLocaleString();
      if (s.category === '物品') document.getElementById('stat-goods').textContent = s.count.toLocaleString();
      if (s.category === '役務') document.getElementById('stat-service').textContent = s.count.toLocaleString();
    });
    document.getElementById('stat-total').textContent = total.toLocaleString();

    // 最新案件
    const latestEl = document.getElementById('latest-items');
    latestEl.innerHTML = '';
    (data.latestItems || []).forEach(item => {
      latestEl.innerHTML += renderListItem(item);
    });

    // 更新時刻
    if (data.lastUpdated) {
      document.getElementById('last-updated').textContent = '最終更新: ' + new Date(data.lastUpdated).toLocaleString('ja-JP');
    }

    document.getElementById('stats-loading').classList.add('hidden');
    document.getElementById('stats-content').classList.remove('hidden');
  } catch(e) {
    document.getElementById('stats-loading').innerHTML = \`<div class="text-center py-8"><i class="fas fa-exclamation-triangle text-yellow-500 text-3xl mb-3"></i><p class="text-gray-600">データの取得に失敗しました</p><p class="text-xs text-gray-400 mt-1">\${e.message}</p></div>\`;
  }
}

// ========================
// カテゴリーページ
// ========================
async function loadCategoryPage(pageId, category, label) {
  const areaId = pageId + '-result-area';
  const area = document.getElementById(areaId);
  area.innerHTML = \`<div class="flex justify-center py-16"><div class="text-center"><div class="loading-spinner mx-auto mb-4"></div><p class="text-gray-500 text-sm">案件を取得中...</p></div></div>\`;

  try {
    const params = { count: 50 };
    if (category) params.category = category;

    // 新着は7日間
    const today = new Date();
    const pastDate = new Date(today);
    pastDate.setDate(pastDate.getDate() - 7);
    params.query = '入札';
    if (pageId === 'new') {
      params.cftIssueDate = formatDateParam(pastDate) + '/';
    }

    const res = await axios.get('/api/search', { params });
    renderResults(areaId, res.data, label);
  } catch(e) {
    area.innerHTML = \`<div class="text-center py-16"><i class="fas fa-exclamation-triangle text-yellow-500 text-3xl mb-3"></i><p class="text-gray-600">取得に失敗しました: \${e.message}</p></div>\`;
  }
}

// ========================
// 検索実行
// ========================
async function doSearch() {
  const query = document.getElementById('s-query').value;
  const orgName = document.getElementById('s-orgname').value;
  const lgCode = document.getElementById('s-lgcode').value;
  const category = document.getElementById('s-category').value;
  const procedure = document.getElementById('s-procedure').value;
  const dateFrom = document.getElementById('s-date-from').value;
  const dateTo = document.getElementById('s-date-to').value;
  const count = document.getElementById('s-count').value;

  const area = document.getElementById('search-result-area');
  area.innerHTML = \`<div class="flex justify-center py-16"><div class="text-center"><div class="loading-spinner mx-auto mb-4"></div><p class="text-gray-500 text-sm">検索中...</p></div></div>\`;

  try {
    const params = { count };
    if (query) params.query = query;
    if (orgName) params.orgName = orgName;
    if (lgCode) params.lgCode = lgCode;
    if (category) params.category = category;
    if (procedure) params.procedureType = procedure;
    if (dateFrom && dateTo) params.cftIssueDate = dateFrom + '/' + dateTo;
    else if (dateFrom) params.cftIssueDate = dateFrom + '/';
    else if (dateTo) params.cftIssueDate = '/' + dateTo;

    if (!query && !orgName && !lgCode) {
      params.query = '入札';
    }

    const res = await axios.get('/api/search', { params });
    renderResults('search-result-area', res.data, '検索結果');
  } catch(e) {
    area.innerHTML = \`<div class="text-center py-16"><i class="fas fa-exclamation-triangle text-yellow-500 text-3xl mb-3"></i><p class="text-gray-600">検索に失敗しました: \${e.message}</p></div>\`;
  }
}

function clearSearch() {
  ['s-query','s-orgname','s-date-from','s-date-to'].forEach(id => document.getElementById(id).value = '');
  ['s-lgcode','s-category','s-procedure'].forEach(id => document.getElementById(id).value = '');
  document.getElementById('search-result-area').innerHTML = '';
}

function doQuickSearch() {
  const val = document.getElementById('quick-search').value.trim();
  if (!val) return;
  showPage('search');
  document.getElementById('s-query').value = val;
  doSearch();
}

function quickSearchTag(tag) {
  document.getElementById('quick-search').value = tag;
  doQuickSearch();
}

// ========================
// 結果レンダリング
// ========================
function renderResults(areaId, data, label) {
  const area = document.getElementById(areaId);
  if (!data || data.error) {
    area.innerHTML = \`<div class="text-center py-16 bg-white rounded-2xl border border-gray-100"><i class="fas fa-exclamation-triangle text-yellow-500 text-3xl mb-3"></i><p class="text-gray-600">エラー: \${data?.error || '不明なエラー'}</p></div>\`;
    return;
  }
  const items = data.items || [];
  const total = data.totalHits || 0;

  if (items.length === 0) {
    area.innerHTML = \`<div class="text-center py-16 bg-white rounded-2xl border border-gray-100"><i class="fas fa-search text-gray-300 text-4xl mb-4"></i><p class="text-gray-500 text-lg">案件が見つかりませんでした</p><p class="text-xs text-gray-400 mt-2">検索条件を変更してお試しください</p></div>\`;
    return;
  }

  let html = \`
    <div class="bg-white rounded-2xl shadow-sm border border-gray-100 mb-6">
      <div class="p-4 border-b border-gray-100 flex items-center justify-between">
        <h3 class="font-bold text-gray-800 text-sm flex items-center gap-2">
          <i class="fas fa-list text-blue-500"></i>
          \${label}
          <span class="ml-2 text-xs bg-blue-50 text-blue-600 px-2 py-0.5 rounded-full font-normal">
            全 \${total.toLocaleString()} 件中 \${items.length} 件表示
          </span>
        </h3>
        <div class="flex gap-2">
          <button onclick="sortResults('date')" class="text-xs text-gray-500 hover:text-blue-600 px-3 py-1.5 border border-gray-200 rounded-lg hover:border-blue-300">
            <i class="fas fa-sort-amount-down mr-1"></i>公告日順
          </button>
          <button onclick="sortResults('deadline')" class="text-xs text-gray-500 hover:text-blue-600 px-3 py-1.5 border border-gray-200 rounded-lg hover:border-blue-300">
            <i class="fas fa-clock mr-1"></i>締切順
          </button>
        </div>
      </div>
      <div id="result-list" class="divide-y divide-gray-50">
  \`;

  items.forEach(item => {
    html += renderListItem(item);
  });

  html += \`</div></div>\`;
  area.innerHTML = html;
  searchResults = items;
}

function renderListItem(item) {
  const catBadge = getCategoryBadge(item.category);
  const procBadge = item.procedureType ? \`<span class="tag bg-gray-100 text-gray-600">\${item.procedureType}</span>\` : '';
  const issueDate = formatDisplayDate(item.cftIssueDate);
  const deadline = formatDisplayDate(item.tenderSubmissionDeadline);
  const openDate = formatDisplayDate(item.openingTendersEvent);
  const deadlineWarning = isDeadlineSoon(item.tenderSubmissionDeadline);

  return \`
    <div class="result-row px-6 py-4 cursor-pointer" onclick='showModal(\${JSON.stringify(item).replace(/'/g, "\\\\'")})'>\`
    + \`
      <div class="flex items-start justify-between gap-4">
        <div class="flex-1 min-w-0">
          <div class="flex flex-wrap items-center gap-2 mb-2">
            \${catBadge}
            \${procBadge}
            \${deadlineWarning ? '<span class="tag bg-red-100 text-red-600"><i class="fas fa-fire-alt mr-1"></i>締切間近</span>' : ''}
          </div>
          <h4 class="text-sm font-semibold text-gray-800 leading-snug mb-2 line-clamp-2 hover:text-blue-600">
            \${escHtml(item.projectName || '（案件名なし）')}
          </h4>
          <div class="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-gray-500">
            \${item.organizationName ? \`<span><i class="fas fa-building mr-1 text-gray-400"></i>\${escHtml(item.organizationName)}</span>\` : ''}
            \${item.prefectureName ? \`<span><i class="fas fa-map-marker-alt mr-1 text-gray-400"></i>\${escHtml(item.prefectureName)}\${item.cityName ? ' ' + escHtml(item.cityName) : ''}</span>\` : ''}
            \${issueDate ? \`<span><i class="fas fa-calendar mr-1 text-gray-400"></i>公告: \${issueDate}</span>\` : ''}
            \${deadline ? \`<span class="\${deadlineWarning ? 'text-red-500 font-medium' : ''}"><i class="fas fa-clock mr-1 text-gray-400"></i>締切: \${deadline}</span>\` : ''}
            \${openDate ? \`<span><i class="fas fa-gavel mr-1 text-gray-400"></i>開札: \${openDate}</span>\` : ''}
          </div>
        </div>
        <div class="flex-shrink-0">
          <i class="fas fa-chevron-right text-gray-300 text-sm mt-1"></i>
        </div>
      </div>
    </div>
  \`;
}

function getCategoryBadge(cat) {
  const map = {
    '物品': 'badge-物品',
    '工事': 'badge-工事',
    '役務': 'badge-役務',
  };
  const cls = map[cat] || 'badge-default';
  return cat ? \`<span class="tag \${cls}">\${escHtml(cat)}</span>\` : '';
}

// ========================
// ソート
// ========================
function sortResults(type) {
  if (!searchResults.length) return;
  const sorted = [...searchResults].sort((a, b) => {
    const dateA = type === 'date' ? (a.cftIssueDate || '') : (a.tenderSubmissionDeadline || '');
    const dateB = type === 'date' ? (b.cftIssueDate || '') : (b.tenderSubmissionDeadline || '');
    return dateB.localeCompare(dateA);
  });

  const list = document.getElementById('result-list');
  if (!list) return;
  list.innerHTML = '';
  sorted.forEach(item => list.innerHTML += renderListItem(item));
  searchResults = sorted;
}

// ========================
// モーダル
// ========================
function showModal(item) {
  document.getElementById('modal-title').textContent = item.projectName || '案件詳細';
  const catBadge = getCategoryBadge(item.category);
  const deadlineWarning = isDeadlineSoon(item.tenderSubmissionDeadline);

  let attHtml = '';
  if (item.attachments && item.attachments.length > 0) {
    attHtml = '<div class="mt-4"><h5 class="text-xs font-semibold text-gray-500 uppercase mb-2">添付ファイル</h5><div class="space-y-1">';
    item.attachments.forEach(att => {
      attHtml += \`<a href="\${escHtml(att.uri)}" target="_blank" class="flex items-center gap-2 text-sm text-blue-600 hover:text-blue-800 hover:underline"><i class="fas fa-paperclip text-gray-400"></i>\${escHtml(att.name)}</a>\`;
    });
    attHtml += '</div></div>';
  }

  const descHtml = item.projectDescription
    ? \`<div class="mt-4"><h5 class="text-xs font-semibold text-gray-500 uppercase mb-2">公告内容</h5><div class="bg-gray-50 rounded-xl p-4 text-xs text-gray-700 leading-relaxed whitespace-pre-wrap max-h-48 overflow-y-auto">\${escHtml(item.projectDescription.substring(0, 1000))}\${item.projectDescription.length > 1000 ? '...' : ''}</div></div>\`
    : '';

  document.getElementById('modal-content').innerHTML = \`
    <div class="space-y-4">
      <div class="flex flex-wrap gap-2">
        \${catBadge}
        \${item.procedureType ? \`<span class="tag bg-gray-100 text-gray-600">\${escHtml(item.procedureType)}</span>\` : ''}
        \${deadlineWarning ? '<span class="tag bg-red-100 text-red-600"><i class="fas fa-fire-alt mr-1"></i>締切間近</span>' : ''}
      </div>

      <h4 class="text-base font-bold text-gray-900 leading-snug">\${escHtml(item.projectName || '（案件名なし）')}</h4>

      <div class="grid grid-cols-2 gap-4">
        \${item.organizationName ? \`<div class="col-span-2"><span class="text-xs text-gray-500">発注機関</span><p class="text-sm font-medium text-gray-800 mt-0.5">\${escHtml(item.organizationName)}</p></div>\` : ''}
        \${item.prefectureName ? \`<div><span class="text-xs text-gray-500">都道府県</span><p class="text-sm font-medium text-gray-800 mt-0.5">\${escHtml(item.prefectureName)}\${item.cityName ? '/' + escHtml(item.cityName) : ''}</p></div>\` : ''}
        \${item.location ? \`<div><span class="text-xs text-gray-500">履行場所</span><p class="text-sm font-medium text-gray-800 mt-0.5">\${escHtml(item.location)}</p></div>\` : ''}
        \${item.cftIssueDate ? \`<div><span class="text-xs text-gray-500">公告日</span><p class="text-sm font-medium text-gray-800 mt-0.5">\${formatDisplayDate(item.cftIssueDate)}</p></div>\` : ''}
        \${item.tenderSubmissionDeadline ? \`<div><span class="text-xs text-gray-500">入札締切日</span><p class="text-sm font-medium \${deadlineWarning ? 'text-red-600' : 'text-gray-800'} mt-0.5">\${formatDisplayDate(item.tenderSubmissionDeadline)}\${deadlineWarning ? ' ⚠️' : ''}</p></div>\` : ''}
        \${item.openingTendersEvent ? \`<div><span class="text-xs text-gray-500">開札日</span><p class="text-sm font-medium text-gray-800 mt-0.5">\${formatDisplayDate(item.openingTendersEvent)}</p></div>\` : ''}
        \${item.periodEndTime ? \`<div><span class="text-xs text-gray-500">納入期限</span><p class="text-sm font-medium text-gray-800 mt-0.5">\${formatDisplayDate(item.periodEndTime)}</p></div>\` : ''}
        \${item.certification ? \`<div><span class="text-xs text-gray-500">入札資格</span><p class="text-sm font-medium text-gray-800 mt-0.5">\${escHtml(item.certification)}</p></div>\` : ''}
      </div>

      \${descHtml}
      \${attHtml}

      \${item.url ? \`
        <div class="pt-4 border-t border-gray-100">
          <a href="\${escHtml(item.url)}" target="_blank" class="inline-flex items-center gap-2 btn-primary text-white px-5 py-2.5 rounded-xl text-sm font-medium shadow-md">
            <i class="fas fa-external-link-alt"></i> 公告原文を開く
          </a>
        </div>
      \` : ''}
    </div>
  \`;
  document.getElementById('modal').classList.remove('hidden');
  document.getElementById('modal').classList.add('flex');
}

function closeModal() {
  document.getElementById('modal').classList.add('hidden');
  document.getElementById('modal').classList.remove('flex');
}

// モーダル外クリックで閉じる
document.getElementById('modal').addEventListener('click', function(e) {
  if (e.target === this) closeModal();
});

// ========================
// ユーティリティ
// ========================
function formatDisplayDate(dateStr) {
  if (!dateStr) return '';
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return dateStr;
  return d.toLocaleDateString('ja-JP', { year: 'numeric', month: '2-digit', day: '2-digit' });
}

function formatDateParam(date) {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const d = String(date.getDate()).padStart(2, '0');
  return y + '-' + m + '-' + d;
}

function isDeadlineSoon(deadline) {
  if (!deadline) return false;
  const d = new Date(deadline);
  if (isNaN(d.getTime())) return false;
  const diff = (d - new Date()) / (1000 * 60 * 60 * 24);
  return diff >= 0 && diff <= 7;
}

function escHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// Enterキーで検索
document.getElementById('s-query').addEventListener('keypress', e => { if (e.key === 'Enter') doSearch(); });
document.getElementById('s-orgname').addEventListener('keypress', e => { if (e.key === 'Enter') doSearch(); });

// 初期表示
loadDashboard();
</script>
</body>
</html>`
}

export default app
