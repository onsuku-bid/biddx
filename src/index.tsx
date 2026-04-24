import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { serveStatic } from 'hono/cloudflare-workers'

type Bindings = {
  RESEND_API_KEY: string
  NOTIFY_EMAILS: string
  NOTIFY_KEYWORDS: string
  NOTIFY_SECRET: string
  APP_PASSWORD: string
}

// =============================
// JWT ユーティリティ (Web Crypto API)
// =============================
async function createJwt(payload: Record<string, any>, secret: string): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' }
  const encode = (obj: any) => btoa(JSON.stringify(obj)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
  const headerB64 = encode(header)
  const payloadB64 = encode(payload)
  const data = `${headerB64}.${payloadB64}`
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data))
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
  return `${data}.${sigB64}`
}

async function verifyJwt(token: string, secret: string): Promise<Record<string, any> | null> {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return null
    const [headerB64, payloadB64, sigB64] = parts
    const data = `${headerB64}.${payloadB64}`
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    )
    const sigBytes = Uint8Array.from(atob(sigB64.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(data))
    if (!valid) return null
    const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')))
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null
    return payload
  } catch {
    return null
  }
}

const app = new Hono<{ Bindings: Bindings }>()

// CORS設定
app.use('/api/*', cors())

// 静的ファイルの提供
app.use('/static/*', serveStatic({ root: './' }))

// =============================
// 認証ミドルウェア（/api/login 以外のAPIを保護）
// =============================
app.use('/api/*', async (c, next) => {
  // 認証不要のパス
  const openPaths = ['/api/login', '/api/notify-check']
  if (openPaths.some(p => c.req.path.startsWith(p))) {
    return next()
  }
  const authHeader = c.req.header('Authorization') || ''
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : ''
  if (!token) {
    return c.json({ error: '認証が必要です', code: 'UNAUTHORIZED' }, 401)
  }
  const secret = c.env.APP_PASSWORD || 'biddx-default-secret'
  const payload = await verifyJwt(token, secret)
  if (!payload) {
    return c.json({ error: 'トークンが無効または期限切れです', code: 'INVALID_TOKEN' }, 401)
  }
  return next()
})

// =============================
// ログインAPI
// =============================
app.post('/api/login', async (c) => {
  try {
    const body = await c.req.json()
    const password = body.password || ''
    const appPassword = c.env.APP_PASSWORD || 'biddx-default-secret'

    if (!password || password !== appPassword) {
      return c.json({ error: 'パスワードが正しくありません' }, 401)
    }

    // JWT生成（24時間有効）
    const payload = {
      sub: 'user',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
    }
    const token = await createJwt(payload, appPassword)

    return c.json({ token, expiresIn: 86400 })
  } catch (e) {
    return c.json({ error: 'ログイン処理に失敗しました' }, 500)
  }
})

// =============================
// UITEC（職業能力開発総合大学校）スクレイピングAPI
// =============================

function scrapeUitec(html: string): any[] {
  const items: any[] = []
  // menu_listのulからリンクを抽出（例: <li><a href="xxx.pdf">令和X年X月X日　案件名</a></li>）
  const liRegex = /<li[^>]*>\s*<a[^>]+href="([^"]*)"[^>]*>([\s\S]*?)<\/a>\s*<\/li>/gi
  let m
  while ((m = liRegex.exec(html)) !== null) {
    let href = m[1]
    const text = m[2].replace(/<[^>]+>/g, '').trim()
    if (!href.endsWith('.pdf') && !href.endsWith('.PDF')) continue
    // テキストから日付と案件名を分離（例: "令和８年３月３０日　案件名"）
    const dateMatch = text.match(/^(令和\s*\d{1,2}\s*年\s*\d{1,2}\s*月\s*\d{1,2}\s*日)\s*[　\s]+(.+)$/)
    let dateStr = '', projectName = text
    if (dateMatch) {
      dateStr = dateMatch[1]
      projectName = dateMatch[2].trim()
    }
    if (!projectName) continue
    if (href.startsWith('/')) href = 'https://www.uitec.jeed.go.jp' + href
    else if (!href.startsWith('http')) href = 'https://www.uitec.jeed.go.jp/topics/tender/' + href
    const cftIssueDate = wareki2iso(dateStr)
    const resultId = `uitec-${cftIssueDate}-${projectName.slice(0, 20)}`
    items.push({
      resultId,
      source: 'uitec',
      organizationName: '職業能力開発総合大学校',
      projectName,
      procedureType: '入札公告',
      cftIssueDate,
      url: href,
      prefectureName: '東京都',
      category: '役務',
      attachments: [{ name: '公告PDF', url: href }],
    })
  }
  return items
}

app.get('/api/uitec', async (c) => {
  const keyword = c.req.query('keyword') || c.req.query('query') || ''
  const searchFields = (c.req.query('searchFields') || 'name').split(',')
  // 2つの個票ページを取得してマージ
  const pages = [
    'https://www.uitec.jeed.go.jp/topics/tender/fp2ce800000000p3.html',
    'https://www.uitec.jeed.go.jp/topics/tender/ka7cok0000005u3v.html',
  ]
  try {
    const allItems: any[] = []
    for (const url of pages) {
      try {
        const res = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' } })
        if (res.ok) {
          const html = await res.text()
          allItems.push(...scrapeUitec(html))
        }
      } catch (_) {}
    }
    // 重複除去
    const seen = new Set<string>()
    const items = allItems.filter(item => {
      if (seen.has(item.resultId)) return false
      seen.add(item.resultId)
      return true
    })
    const filtered = keyword ? filterItemsByKeyword(items, keyword, searchFields) : items
    return c.json({ source: '職業能力開発総合大学校', totalHits: filtered.length, items: filtered })
  } catch (e) {
    return c.json({ error: String(e) }, 500)
  }
})

// =============================
// 大阪市デジタル統括室 スクレイピングAPI
// =============================

function scrapeOsakaCity(html: string): any[] {
  const items: any[] = []
  // <div class="sec_01"><h2><a href="...">案件名</a></h2><table>...</table></div>
  const secRegex = /<div class="sec_01">([\s\S]*?)<\/div>/gi
  let m
  while ((m = secRegex.exec(html)) !== null) {
    const sec = m[1]
    const titleMatch = sec.match(/<h2[^>]*>[\s\S]*?<a[^>]+href="([^"]*)"[^>]*>([\s\S]*?)<\/a>/)
    if (!titleMatch) continue
    let url = titleMatch[1]
    if (url.startsWith('/')) url = 'https://www.city.osaka.lg.jp' + url
    const projectName = titleMatch[2].replace(/<[^>]+>/g, '').trim()
    if (!projectName) continue
    // tableのth/tdペアを解析
    const tdData: Record<string, string> = {}
    const rowReg = /<tr>([\s\S]*?)<\/tr>/gi
    let row
    while ((row = rowReg.exec(sec)) !== null) {
      const th = row[1].match(/<th[^>]*>([\s\S]*?)<\/th>/i)
      const td = row[1].match(/<td[^>]*>([\s\S]*?)<\/td>/i)
      if (th && td) {
        tdData[th[1].replace(/<[^>]+>/g, '').trim()] = td[1].replace(/<[^>]+>/g, '').trim()
      }
    }
    const postDateRaw = tdData['公告（公開）日'] || ''
    const deadlineRaw = tdData['入札（締切）日時'] || ''
    const cftIssueDate = wareki2iso(postDateRaw)
    // 締切日から日付部分だけ抽出して変換
    const deadlineDateMatch = deadlineRaw.match(/令和\d{1,2}年\d{1,2}月\d{1,2}日/)
    const tenderDeadline = deadlineDateMatch ? wareki2iso(deadlineDateMatch[0]) : ''
    const resultId = `osaka-${cftIssueDate}-${projectName.slice(0, 20)}`
    items.push({
      resultId,
      source: 'osaka',
      organizationName: '大阪市デジタル統括室',
      projectName,
      procedureType: tdData['入札契約方式'] || '一般競争入札',
      cftIssueDate,
      tenderDeadline,
      url,
      prefectureName: '大阪府',
      category: '役務',
      attachments: [],
    })
  }
  return items
}

app.get('/api/osaka', async (c) => {
  const keyword = c.req.query('keyword') || c.req.query('query') || ''
  const searchFields = (c.req.query('searchFields') || 'name').split(',')
  try {
    const res = await fetch('https://www.city.osaka.lg.jp/templates/gyomuitaku_nyusatsuanken/98-Curr.html', {
      headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' }
    })
    if (!res.ok) return c.json({ error: `取得失敗: ${res.status}` }, 500)
    const html = await res.text()
    let items = scrapeOsakaCity(html)
    if (keyword) items = filterItemsByKeyword(items, keyword, searchFields)
    return c.json({ source: '大阪市デジタル統括室', totalHits: items.length, items })
  } catch (e) {
    return c.json({ error: String(e) }, 500)
  }
})

// =============================
// 北海道情報政策課 スクレイピングAPI
// =============================

function scrapeHokkaido(html: string): any[] {
  const items: any[] = []
  // <article class="item-xxx"><header><time datetime="YYYY-MM-DD">...</time><h2><a href="...">案件名</a></h2></header></article>
  const articleReg = /<article[^>]*>([\s\S]*?)<\/article>/gi
  let m
  while ((m = articleReg.exec(html)) !== null) {
    const art = m[1]
    const timeMatch = art.match(/<time[^>]+datetime="([^"]+)"/)
    const linkMatch = art.match(/<h2[^>]*>[\s\S]*?<a[^>]+href="([^"]*)"[^>]*>([\s\S]*?)<\/a>/)
    if (!timeMatch || !linkMatch) continue
    const cftIssueDate = timeMatch[1] // YYYY-MM-DD形式
    let url = linkMatch[1]
    if (url.startsWith('/')) url = 'https://www.pref.hokkaido.lg.jp' + url
    const projectName = linkMatch[2].replace(/<[^>]+>/g, '').trim()
    if (!projectName) continue
    const resultId = `hokkaido-${cftIssueDate}-${projectName.slice(0, 20)}`
    items.push({
      resultId,
      source: 'hokkaido',
      organizationName: '北海道 情報政策課',
      projectName,
      procedureType: '一般競争入札',
      cftIssueDate: cftIssueDate + 'T00:00:00+09:00',
      url,
      prefectureName: '北海道',
      category: '役務',
      attachments: [],
    })
  }
  return items
}

app.get('/api/hokkaido', async (c) => {
  const keyword = c.req.query('keyword') || c.req.query('query') || ''
  const searchFields = (c.req.query('searchFields') || 'name').split(',')
  try {
    const res = await fetch('https://www.pref.hokkaido.lg.jp/sm/jsk/a0001/b0002/', {
      headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' }
    })
    if (!res.ok) return c.json({ error: `取得失敗: ${res.status}` }, 500)
    const html = await res.text()
    let items = scrapeHokkaido(html)
    if (keyword) items = filterItemsByKeyword(items, keyword, searchFields)
    return c.json({ source: '北海道 情報政策課', totalHits: items.length, items })
  } catch (e) {
    return c.json({ error: String(e) }, 500)
  }
})

// =============================
// 今治市産業振興課 スクレイピングAPI
// =============================

function scrapeImabari(html: string): any[] {
  const items: any[] = []
  // <dl><dt>2026年4月3日</dt><dd><a href="...">案件名</a></dd></dl>
  const dtReg = /<dt>([\s\S]*?)<\/dt>\s*<dd>([\s\S]*?)<\/dd>/gi
  let m
  while ((m = dtReg.exec(html)) !== null) {
    const dateRaw = m[1].replace(/<[^>]+>/g, '').trim()
    const dd = m[2]
    // プロポーザル案件のみ（ddのリンクが/sangyou/proposal/のパスを含む）
    const linkMatch = dd.match(/<a[^>]+href="([^"]*)"[^>]*>([\s\S]*?)<\/a>/)
    if (!linkMatch) continue
    if (!linkMatch[1].includes('/sangyou/')) continue
    const projectName = linkMatch[2].replace(/<[^>]+>/g, '').trim()
    if (!projectName) continue
    // 質問回答更新などの更新情報を除外（案件公告のみ残す）
    if (projectName.includes('質問') || projectName.includes('回答') || projectName.includes('選定結果')) continue
    // 日付変換（YYYY年M月D日）
    const dMatch = dateRaw.match(/(\d{4})年(\d{1,2})月(\d{1,2})日/)
    const cftIssueDate = dMatch ? `${dMatch[1]}-${dMatch[2].padStart(2,'0')}-${dMatch[3].padStart(2,'0')}T00:00:00+09:00` : ''
    let url = linkMatch[1]
    if (url.startsWith('/')) url = 'https://www.city.imabari.ehime.jp' + url
    const resultId = `imabari-${cftIssueDate}-${projectName.slice(0, 20)}`
    items.push({
      resultId,
      source: 'imabari',
      organizationName: '今治市 産業振興課',
      projectName,
      procedureType: '公募型プロポーザル',
      cftIssueDate,
      url,
      prefectureName: '愛媛県',
      category: '役務',
      attachments: [],
    })
  }
  return items
}

app.get('/api/imabari', async (c) => {
  const keyword = c.req.query('keyword') || c.req.query('query') || ''
  const searchFields = (c.req.query('searchFields') || 'name').split(',')
  try {
    const res = await fetch('https://www.city.imabari.ehime.jp/sangyou/new.html', {
      headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' }
    })
    if (!res.ok) return c.json({ error: `取得失敗: ${res.status}` }, 500)
    const html = await res.text()
    let items = scrapeImabari(html)
    if (keyword) items = filterItemsByKeyword(items, keyword, searchFields)
    return c.json({ source: '今治市 産業振興課', totalHits: items.length, items })
  } catch (e) {
    return c.json({ error: String(e) }, 500)
  }
})

// =============================
// 長野県営業局 スクレイピングAPI
// =============================

function scrapeNagano(html: string): any[] {
  const items: any[] = []
  // <h2>または<h3>で区切られた案件ブロック、その後にtableで詳細
  // h2タグで案件名を取得
  const h2Reg = /<h[23][^>]*>([\s\S]*?)<\/h[23]>/gi
  let m
  const projectNames: string[] = []
  while ((m = h2Reg.exec(html)) !== null) {
    const t = m[1].replace(/<[^>]+>/g, '').trim()
    if (t && !t.includes('トップ') && !t.includes('更新') && !t.includes('サイト') && !t.includes('お問')) {
      projectNames.push(t)
    }
  }
  // tableの行から日付を抽出
  const tables: string[] = []
  const tableReg = /<table[^>]*>([\s\S]*?)<\/table>/gi
  while ((m = tableReg.exec(html)) !== null) {
    tables.push(m[1])
  }
  // 案件名とtableを対応付け（順序でマッチング）
  projectNames.forEach((projectName, i) => {
    const table = tables[i] || ''
    // 公告日を探す
    const dateRow = table.match(/公告日[\s\S]*?<td[^>]*>([\s\S]*?)<\/td>/i)
    const dateRaw = dateRow ? dateRow[1].replace(/<[^>]+>/g, '').trim() : ''
    // 全角数字 → 半角
    const dateNorm = dateRaw.replace(/[０-９]/g, s => String.fromCharCode(s.charCodeAt(0) - 0xFEE0))
    const dMatch = dateNorm.match(/令和\s*(\d{1,2})\s*年\s*(\d{1,2})\s*月\s*(\d{1,2})\s*日/)
    let cftIssueDate = ''
    if (dMatch) {
      const y = 2018 + parseInt(dMatch[1])
      const mo = dMatch[2].padStart(2, '0')
      const d = dMatch[3].padStart(2, '0')
      cftIssueDate = `${y}-${mo}-${d}T00:00:00+09:00`
    }
    // PDFリンクを探す
    const pdfMatch = table.match(/href="([^"]*\.pdf[^"]*)"/i) || html.match(new RegExp(`href="([^"]*\\.pdf[^"]*)"`, 'i'))
    let url = pdfMatch ? pdfMatch[1] : 'https://www.pref.nagano.lg.jp/eigyo/0415propo.html'
    if (url.startsWith('/')) url = 'https://www.pref.nagano.lg.jp' + url
    const resultId = `nagano-${cftIssueDate}-${projectName.slice(0, 20)}`
    items.push({
      resultId,
      source: 'nagano',
      organizationName: '長野県 営業局',
      projectName,
      procedureType: '公募型プロポーザル',
      cftIssueDate,
      url,
      prefectureName: '長野県',
      category: '役務',
      attachments: [],
    })
  })
  return items
}

app.get('/api/nagano', async (c) => {
  const keyword = c.req.query('keyword') || c.req.query('query') || ''
  const searchFields = (c.req.query('searchFields') || 'name').split(',')
  try {
    const res = await fetch('https://www.pref.nagano.lg.jp/eigyo/0415propo.html', {
      headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' }
    })
    if (!res.ok) return c.json({ error: `取得失敗: ${res.status}` }, 500)
    const html = await res.text()
    let items = scrapeNagano(html)
    if (keyword) items = filterItemsByKeyword(items, keyword, searchFields)
    return c.json({ source: '長野県 営業局', totalHits: items.length, items })
  } catch (e) {
    return c.json({ error: String(e) }, 500)
  }
})

// =============================
// JEED（独立行政法人高齢・障害・求職者雇用支援機構）スクレイピングAPI
// =============================

function scrapeJeed(html: string): any[] {
  const items: any[] = []
  // ul.nyusatsuの中のliを抽出
  const ulRegex = /<ul class="nyusatsu">([\s\S]*?)<\/ul>/gi
  let ulMatch
  while ((ulMatch = ulRegex.exec(html)) !== null) {
    const ulHtml = ulMatch[1]
    const liRegex = /<li[^>]*>([\s\S]*?)<\/li>/gi
    let liMatch
    while ((liMatch = liRegex.exec(ulHtml)) !== null) {
      const liHtml = liMatch[1]

      // 日付 (.date)
      const dateMatch = liHtml.match(/<div class="date"[^>]*>([\s\S]*?)<\/div>/i)
      const dateRaw = dateMatch ? dateMatch[1].replace(/<[^>]+>/g, '').trim() : ''
      const cftIssueDate = wareki2iso(dateRaw)

      // 案件名 (.title a)
      const titleMatch = liHtml.match(/<div class="title"[^>]*>[\s\S]*?<a[^>]+href="([^"]*)"[^>]*>([\s\S]*?)<\/a>/i)
      if (!titleMatch) continue
      let pdfUrl = titleMatch[1]
      // 相対URLを絶対URLに変換
      if (pdfUrl.startsWith('/')) pdfUrl = 'https://www.jeed.go.jp' + pdfUrl
      const projectName = titleMatch[2].replace(/<[^>]+>/g, '').trim()
        .replace(/（PDF[^）]*）/g, '').trim()
      if (!projectName) continue

      // 締切日（.bikou 内の「終了：」）
      const bikouMatch = liHtml.match(/終了：([^<\n]+)/)
      const deadlineRaw = bikouMatch ? bikouMatch[1].trim() : ''
      const tenderDeadline = wareki2iso(deadlineRaw)

      // 添付ファイル（.shiryou内のリンク）
      const attachments: any[] = []
      const attachRegex = /<a[^>]+href="([^"]*)"[^>]*>([\s\S]*?)<\/a>/gi
      let attachMatch
      const shiryouMatch = liHtml.match(/<div class="shiryou">([\s\S]*?)<\/div>/i)
      if (shiryouMatch) {
        while ((attachMatch = attachRegex.exec(shiryouMatch[1])) !== null) {
          let aUrl = attachMatch[1]
          if (aUrl.startsWith('/')) aUrl = 'https://www.jeed.go.jp' + aUrl
          const aName = attachMatch[2].replace(/<[^>]+>/g, '').trim()
          if (aName) attachments.push({ name: aName, url: aUrl })
        }
      }

      const resultId = `jeed-${cftIssueDate}-${projectName.slice(0, 20)}`
      items.push({
        resultId,
        source: 'jeed',
        organizationName: '独立行政法人高齢・障害・求職者雇用支援機構',
        projectName,
        procedureType: '一般競争入札',
        cftIssueDate,
        tenderDeadline,
        url: pdfUrl,
        prefectureName: '東京都',
        category: '役務',
        attachments,
      })
    }
  }
  return items
}

app.get('/api/jeed', async (c) => {
  const keyword = c.req.query('keyword') || c.req.query('query') || ''
  const searchFields = (c.req.query('searchFields') || 'name').split(',')
  try {
    const res = await fetch('https://www.jeed.go.jp/jeed/information/honbu/chotatsu_buppin.html', {
      headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' }
    })
    if (!res.ok) return c.json({ error: `取得失敗: ${res.status}` }, 500)
    const html = await res.text()
    let items = scrapeJeed(html)
    if (keyword) items = filterItemsByKeyword(items, keyword, searchFields)
    return c.json({ source: '独立行政法人高齢・障害・求職者雇用支援機構', totalHits: items.length, items })
  } catch (e) {
    return c.json({ error: String(e) }, 500)
  }
})

// =============================
// IPA（独立行政法人情報処理推進機構）スクレイピング
// =============================

function scrapeIpa(html: string): any[] {
  const items: any[] = []
  // <li class="news-list__item"> の中に日付 news-list__date と タイトル news-list__ttl、リンクhrefがある
  const liRegex = /<li class="news-list__item"[^>]*>([\s\S]*?)<\/li>/gi
  let liMatch
  while ((liMatch = liRegex.exec(html)) !== null) {
    const liHtml = liMatch[1]

    // リンクURL
    const linkMatch = liHtml.match(/<a[^>]+href="([^"]*)"[^>]*>/)
    if (!linkMatch) continue
    let url = linkMatch[1]
    if (url.startsWith('/')) url = 'https://www.ipa.go.jp' + url

    // 日付 <p class="news-list__date">YYYY年M月D日</p>
    const dateMatch = liHtml.match(/<p class="news-list__date">([^<]+)<\/p>/i)
    const dateRaw = dateMatch ? dateMatch[1].trim() : ''
    const dateIso = dateRaw.replace(/(\d{4})年(\d{1,2})月(\d{1,2})日/, (_, y, m, d) =>
      `${y}-${m.padStart(2,'0')}-${d.padStart(2,'0')}`)

    // タイトル <p class="news-list__ttl">...</p>
    const titleMatch = liHtml.match(/<p class="news-list__ttl">([\s\S]*?)<\/p>/i)
    const projectName = titleMatch ? titleMatch[1].replace(/<[^>]+>/g, '').trim() : ''
    if (!projectName) continue

    const resultId = `ipa-${dateIso}-${projectName.slice(0, 20)}`
    items.push({
      resultId,
      source: 'ipa',
      organizationName: '独立行政法人情報処理推進機構（IPA）',
      projectName,
      procedureType: '一般競争入札',
      cftIssueDate: dateIso,
      url,
      prefectureName: '東京都',
      category: '役務',
      attachments: [],
    })
  }
  return items
}

app.get('/api/ipa', async (c) => {
  const keyword = c.req.query('keyword') || c.req.query('query') || ''
  const searchFields = (c.req.query('searchFields') || 'name').split(',')
  try {
    const res = await fetch('https://www.ipa.go.jp/choutatsu/nyusatsu/2026/index.html', {
      headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' }
    })
    if (!res.ok) return c.json({ error: `取得失敗: ${res.status}` }, 500)
    const html = await res.text()
    let items = scrapeIpa(html)
    if (keyword) items = filterItemsByKeyword(items, keyword, searchFields)
    return c.json({ source: '独立行政法人情報処理推進機構（IPA）', totalHits: items.length, items })
  } catch (e) {
    return c.json({ error: String(e) }, 500)
  }
})

// =============================
// 防災科研（国立研究開発法人防災科学技術研究所）スクレイピング
// =============================

function scrapeBosai(html: string): any[] {
  const items: any[] = []
  // <TR><TD>YYYY.MM.DD</TD><TD class="link4"><A href="...">案件名</A></TD></TR>
  const rowRegex = /<TR[^>]*>\s*<TD[^>]*>(\d{4}\.\d{2}\.\d{2})<\/TD>\s*<TD[^>]*class="link4"[^>]*><A[^>]+href="([^"]*)"[^>]*>([\s\S]*?)<\/A><\/TD>\s*<\/TR>/gi
  let match
  while ((match = rowRegex.exec(html)) !== null) {
    const dateRaw = match[1] // YYYY.MM.DD
    const dateIso = dateRaw.replace(/(\d{4})\.(\d{2})\.(\d{2})/, '$1-$2-$3')
    let url = match[2]
    if (!url.startsWith('http')) {
      url = 'https://www.bosai.go.jp/kokai/nyuusatsu/' + url.replace(/^\.?\//, '')
    }
    const projectName = match[3].replace(/<[^>]+>/g, '').trim()
    if (!projectName || projectName.includes('ひながた') || projectName.startsWith('★')) continue

    const resultId = `bosai-${dateIso}-${projectName.slice(0, 20)}`
    items.push({
      resultId,
      source: 'bosai',
      organizationName: '国立研究開発法人防災科学技術研究所',
      projectName,
      procedureType: '一般競争入札',
      cftIssueDate: dateIso,
      url,
      prefectureName: '茨城県',
      category: '役務',
      attachments: [{ name: '入札公告PDF', url }],
    })
  }
  return items
}

app.get('/api/bosai', async (c) => {
  const keyword = c.req.query('keyword') || c.req.query('query') || ''
  const searchFields = (c.req.query('searchFields') || 'name').split(',')
  try {
    const res = await fetch('https://www.bosai.go.jp/kokai/nyuusatsu/index.html', {
      headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' }
    })
    if (!res.ok) return c.json({ error: `取得失敗: ${res.status}` }, 500)
    const html = await res.text()
    let items = scrapeBosai(html)
    if (keyword) items = filterItemsByKeyword(items, keyword, searchFields)
    return c.json({ source: '国立研究開発法人防災科学技術研究所', totalHits: items.length, items })
  } catch (e) {
    return c.json({ error: String(e) }, 500)
  }
})

// =============================
// JFC（株式会社日本政策金融公庫）スクレイピングAPI
// =============================

function scrapeJfc(html: string): any[] {
  const items: any[] = []
  // p-page-supply-bid-1-bid-item クラスのli要素を抽出
  const liRegex = /<li class="p-page-supply-bid-1-bid-item[^"]*"[^>]*>([\s\S]*?)<\/li>/gi
  let liMatch
  while ((liMatch = liRegex.exec(html)) !== null) {
    const liHtml = liMatch[1]

    // 各dlのdt/ddペアを抽出
    const dlData: Record<string, string> = {}
    const dlRegex = /<dl[^>]*>([\s\S]*?)<\/dl>/gi
    let dlMatch
    while ((dlMatch = dlRegex.exec(liHtml)) !== null) {
      const dtMatch = dlMatch[1].match(/<dt>([\s\S]*?)<\/dt>/i)
      const ddMatch = dlMatch[1].match(/<dd[^>]*>([\s\S]*?)<\/dd>/i)
      if (dtMatch && ddMatch) {
        const key = dtMatch[1].replace(/<[^>]+>/g, '').trim()
        const val = ddMatch[1].replace(/<[^>]+>/g, '').trim()
        dlData[key] = val
      }
    }

    // 案件名と添付PDFのURL
    const linkMatch = liHtml.match(/<dd class="link"[^>]*>[\s\S]*?<a[^>]+href="([^"]*)"[^>]*>([\s\S]*?)<\/a>/i)
    if (!linkMatch) continue
    let pdfUrl = linkMatch[1]
    if (pdfUrl.startsWith('/')) pdfUrl = 'https://www.jfc.go.jp' + pdfUrl
    const projectName = (dlData['案件名：'] || linkMatch[2].replace(/<[^>]+>/g, '')).trim()
    if (!projectName) continue

    // 掲載日（YYYY年MM月DD日 → YYYY-MM-DD）
    const postDateRaw = dlData['掲載日（入札公告日）：'] || ''
    const postDateMatch = postDateRaw.match(/(\d{4})年(\d{2})月(\d{2})日/)
    const cftIssueDate = postDateMatch
      ? `${postDateMatch[1]}-${postDateMatch[2]}-${postDateMatch[3]}`
      : ''

    // 開札日時
    const openDateRaw = dlData['開札日時：'] || ''
    const openDateMatch = openDateRaw.match(/(\d{4})年(\d{2})月(\d{2})日/)
    const tenderDeadline = openDateMatch
      ? `${openDateMatch[1]}-${openDateMatch[2]}-${openDateMatch[3]}`
      : ''

    const resultId = `jfc-${cftIssueDate}-${projectName.slice(0, 20)}`
    items.push({
      resultId,
      source: 'jfc',
      organizationName: '株式会社日本政策金融公庫',
      projectName,
      procedureType: '一般競争入札',
      cftIssueDate,
      tenderDeadline,
      url: pdfUrl,
      prefectureName: '東京都',
      category: '役務',
      attachments: [{ name: '入札公告PDF', url: pdfUrl }],
    })
  }
  return items
}

app.get('/api/jfc', async (c) => {
  const keyword = c.req.query('keyword') || c.req.query('query') || ''
  const searchFields = (c.req.query('searchFields') || 'name').split(',')
  try {
    const res = await fetch('https://www.jfc.go.jp/n/supply/bid_1.html', {
      headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' }
    })
    if (!res.ok) return c.json({ error: `取得失敗: ${res.status}` }, 500)
    const html = await res.text()
    let items = scrapeJfc(html)
    if (keyword) items = filterItemsByKeyword(items, keyword, searchFields)
    return c.json({ source: '株式会社日本政策金融公庫', totalHits: items.length, items })
  } catch (e) {
    return c.json({ error: String(e) }, 500)
  }
})

// =============================
// 企業年金連合会 スクレイピングAPI
// =============================

app.get('/api/pfa', async (c) => {
  const keyword = c.req.query('keyword') || c.req.query('query') || ''
  const searchFields = (c.req.query('searchFields') || 'name').split(',')
  try {
    const res = await fetch('https://www.pfa.or.jp/chotatsu/ichiran/index.html', {
      headers: { 'User-Agent': 'BidSearchApp/1.0' }
    })
    if (!res.ok) {
      return c.json({ error: `取得失敗: ${res.status}` }, 500)
    }
    const html = await res.text()
    let items = scrapePfa(html)

    if (keyword) {
      items = filterItemsByKeyword(items, keyword, searchFields)
    }

    return c.json({ source: '企業年金連合会', totalHits: items.length, items })
  } catch (e) {
    return c.json({ error: String(e) }, 500)
  }
})

function scrapePfa(html: string): any[] {
  const items: any[] = []

  // テーブル行をパース: <tr><th scope="row">令和X年Y月Z日</th><td>案件名</td><td>ZIP</td><td>PDF</td><td>落札PDF</td></tr>
  const rowRegex = /<tr[^>]*>([\s\S]*?)<\/tr>/gi
  let rowMatch
  while ((rowMatch = rowRegex.exec(html)) !== null) {
    const rowHtml = rowMatch[1]

    // th[scope=row] から日付を取得
    const thMatch = rowHtml.match(/<th[^>]*scope=["']?row["']?[^>]*>([\s\S]*?)<\/th>/i)
    if (!thMatch) continue
    const dateRaw = thMatch[1].replace(/<[^>]+>/g, '').trim()
    // 和暦の日付でなければスキップ
    if (!/令和|平成/.test(dateRaw)) continue

    // tdを抽出
    const tds: string[] = []
    const tdRegex = /<td[^>]*>([\s\S]*?)<\/td>/gi
    let tdMatch
    while ((tdMatch = tdRegex.exec(rowHtml)) !== null) {
      tds.push(tdMatch[1])
    }
    if (tds.length < 1) continue

    // td[0] = 案件名
    const projectName = tds[0].replace(/<[^>]+>/g, '').trim()
    if (!projectName) continue

    // td[1] = 入札説明書(ZIP), td[2] = 公告(PDF), td[3] = 落札(PDF)
    const attachments: any[] = []
    let mainUrl = ''

    const labelMap: Record<number, string> = {
      1: '入札説明書',
      2: '公告PDF',
      3: '落札（契約）PDF',
    }

    for (let i = 1; i < tds.length && i <= 3; i++) {
      const linkMatches = [...tds[i].matchAll(/<a[^>]+href="([^"]+)"[^>]*>/gi)]
      for (const lm of linkMatches) {
        let uri = lm[1]
        // 既に絶対URLの場合はそのまま
        if (!uri.startsWith('http')) {
          uri = 'https://www.pfa.or.jp' + (uri.startsWith('/') ? uri : '/chotatsu/ichiran/' + uri)
        }
        const label = labelMap[i] || `添付${i}`
        attachments.push({ name: label, uri })
        // 公告PDFをメインURLにする
        if (i === 2 && !mainUrl) mainUrl = uri
      }
    }
    // 公告PDFがない場合、入札説明書のURLをメインに
    if (!mainUrl && attachments.length > 0) mainUrl = attachments[0].uri

    const dateIso = convertJapaneseDate(dateRaw)

    items.push({
      source: '企業年金連合会',
      organizationName: '企業年金連合会',
      projectName,
      procedureType: '一般競争入札',
      cftIssueDate: dateIso,
      url: mainUrl || 'https://www.pfa.or.jp/chotatsu/ichiran/index.html',
      prefectureName: '東京都',
      category: '役務',
      attachments,
    })
  }
  return items
}

// 日本語和暦→ISO日付変換
function convertJapaneseDate(dateStr: string): string {
  const m = dateStr.match(/令和(\d+)年(\d+)月(\d+)日/)
  if (m) {
    const year = 2018 + parseInt(m[1])
    const month = m[2].padStart(2, '0')
    const day = m[3].padStart(2, '0')
    return `${year}-${month}-${day}T00:00:00+09:00`
  }
  const m2 = dateStr.match(/平成(\d+)年(\d+)月(\d+)日/)
  if (m2) {
    const year = 1988 + parseInt(m2[1])
    const month = m2[2].padStart(2, '0')
    const day = m2[3].padStart(2, '0')
    return `${year}-${month}-${day}T00:00:00+09:00`
  }
  return dateStr
}

// =============================
// 一括検索API（全ソース横断）
// =============================

app.get('/api/search-all', async (c) => {
  const keyword = c.req.query('keyword') || ''
  const sources = (c.req.query('sources') || 'kkj,kyoukaikenpo,pfa,jeed,jfc').split(',')
  const searchFields = (c.req.query('searchFields') || 'name').split(',')

  const results: any[] = []
  const errors: Record<string, string> = {}

  await Promise.allSettled([
    // 官公需API
    sources.includes('kkj') ? (async () => {
      try {
        const params = new URLSearchParams({ Query: keyword || '入札', Count: '30' })
        const res = await fetch(`http://www.kkj.go.jp/api/?${params.toString()}`, {
          headers: { 'User-Agent': 'BidSearchApp/1.0' }
        })
        const xml = await res.text()
        const parsed = parseKkjXml(xml)
        let items = (parsed.items || []).map((item: any) => ({ ...item, source: '官公需ポータル' }))
        if (keyword) items = filterItemsByKeyword(items, keyword, searchFields)
        results.push(...items)
      } catch(e) { errors['kkj'] = String(e) }
    })() : Promise.resolve(),

    // 協会けんぽ
    sources.includes('kyoukaikenpo') ? (async () => {
      try {
        const res = await fetch('https://www.kyoukaikenpo.or.jp/disclosure/procurement/', {
          headers: { 'User-Agent': 'BidSearchApp/1.0' }
        })
        const html = await res.text()
        const items = scrapeKyoukaikenpo(html, 'https://www.kyoukaikenpo.or.jp/disclosure/procurement/')
        const filtered = keyword ? filterItemsByKeyword(items, keyword, searchFields) : items
        results.push(...filtered)
      } catch(e) { errors['kyoukaikenpo'] = String(e) }
    })() : Promise.resolve(),

    // 企業年金連合会
    sources.includes('pfa') ? (async () => {
      try {
        const res = await fetch('https://www.pfa.or.jp/chotatsu/ichiran/index.html', {
          headers: { 'User-Agent': 'BidSearchApp/1.0' }
        })
        const html = await res.text()
        const items = scrapePfa(html)
        const filtered = keyword ? filterItemsByKeyword(items, keyword, searchFields) : items
        results.push(...filtered)
      } catch(e) { errors['pfa'] = String(e) }
    })() : Promise.resolve(),

    // JEED（高齢・障害・求職者雇用支援機構）
    sources.includes('jeed') ? (async () => {
      try {
        const res = await fetch('https://www.jeed.go.jp/jeed/information/honbu/chotatsu_buppin.html', {
          headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' }
        })
        const html = await res.text()
        const items = scrapeJeed(html)
        const filtered = keyword ? filterItemsByKeyword(items, keyword, searchFields) : items
        results.push(...filtered)
      } catch(e) { errors['jeed'] = String(e) }
    })() : Promise.resolve(),

    // JFC（日本政策金融公庫）
    sources.includes('jfc') ? (async () => {
      try {
        const res = await fetch('https://www.jfc.go.jp/n/supply/bid_1.html', {
          headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' }
        })
        const html = await res.text()
        const items = scrapeJfc(html)
        const filtered = keyword ? filterItemsByKeyword(items, keyword, searchFields) : items
        results.push(...filtered)
      } catch(e) { errors['jfc'] = String(e) }
    })() : Promise.resolve(),

    // 金融庁
    sources.includes('fsa') ? (async () => {
      try {
        const res = await fetch('https://www.fsa.go.jp/choutatu/choutatu_j/nyusatu_menu.html', {
          headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' }
        })
        const html = await res.text()
        const items = scrapeFsa(html)
        const filtered = keyword ? filterItemsByKeyword(items, keyword, searchFields) : items
        results.push(...filtered)
      } catch(e) { errors['fsa'] = String(e) }
    })() : Promise.resolve(),

    // UITEC（職業能力開発総合大学校）
    sources.includes('uitec') ? (async () => {
      try {
        const pages = [
          'https://www.uitec.jeed.go.jp/topics/tender/fp2ce800000000p3.html',
          'https://www.uitec.jeed.go.jp/topics/tender/ka7cok0000005u3v.html',
        ]
        const allUitecItems: any[] = []
        for (const url of pages) {
          try {
            const r = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' } })
            if (r.ok) allUitecItems.push(...scrapeUitec(await r.text()))
          } catch (_) {}
        }
        const seen = new Set<string>()
        const items = allUitecItems.filter(i => { if (seen.has(i.resultId)) return false; seen.add(i.resultId); return true })
        const filtered = keyword ? filterItemsByKeyword(items, keyword, searchFields) : items
        results.push(...filtered)
      } catch(e) { errors['uitec'] = String(e) }
    })() : Promise.resolve(),

    // 大阪市デジタル統括室
    sources.includes('osaka') ? (async () => {
      try {
        const res = await fetch('https://www.city.osaka.lg.jp/templates/gyomuitaku_nyusatsuanken/98-Curr.html', {
          headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' }
        })
        const html = await res.text()
        const items = scrapeOsakaCity(html)
        const filtered = keyword ? filterItemsByKeyword(items, keyword, searchFields) : items
        results.push(...filtered)
      } catch(e) { errors['osaka'] = String(e) }
    })() : Promise.resolve(),

    // 北海道情報政策課
    sources.includes('hokkaido') ? (async () => {
      try {
        const res = await fetch('https://www.pref.hokkaido.lg.jp/sm/jsk/a0001/b0002/', {
          headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' }
        })
        const html = await res.text()
        const items = scrapeHokkaido(html)
        const filtered = keyword ? filterItemsByKeyword(items, keyword, searchFields) : items
        results.push(...filtered)
      } catch(e) { errors['hokkaido'] = String(e) }
    })() : Promise.resolve(),

    // 今治市産業振興課
    sources.includes('imabari') ? (async () => {
      try {
        const res = await fetch('https://www.city.imabari.ehime.jp/sangyou/new.html', {
          headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' }
        })
        const html = await res.text()
        const items = scrapeImabari(html)
        const filtered = keyword ? filterItemsByKeyword(items, keyword, searchFields) : items
        results.push(...filtered)
      } catch(e) { errors['imabari'] = String(e) }
    })() : Promise.resolve(),

    // 長野県営業局
    sources.includes('nagano') ? (async () => {
      try {
        const res = await fetch('https://www.pref.nagano.lg.jp/eigyo/0415propo.html', {
          headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' }
        })
        const html = await res.text()
        const items = scrapeNagano(html)
        const filtered = keyword ? filterItemsByKeyword(items, keyword, searchFields) : items
        results.push(...filtered)
      } catch(e) { errors['nagano'] = String(e) }
    })() : Promise.resolve(),

    // IPA（情報処理推進機構）
    sources.includes('ipa') ? (async () => {
      try {
        const res = await fetch('https://www.ipa.go.jp/choutatsu/nyusatsu/2026/index.html', {
          headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' }
        })
        const html = await res.text()
        const items = scrapeIpa(html)
        const filtered = keyword ? filterItemsByKeyword(items, keyword, searchFields) : items
        results.push(...filtered)
      } catch(e) { errors['ipa'] = String(e) }
    })() : Promise.resolve(),

    // 防災科研
    sources.includes('bosai') ? (async () => {
      try {
        const res = await fetch('https://www.bosai.go.jp/kokai/nyuusatsu/index.html', {
          headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' }
        })
        const html = await res.text()
        const items = scrapeBosai(html)
        const filtered = keyword ? filterItemsByKeyword(items, keyword, searchFields) : items
        results.push(...filtered)
      } catch(e) { errors['bosai'] = String(e) }
    })() : Promise.resolve(),
  ])

  // 公告日降順でソート
  results.sort((a, b) => {
    const da = a.cftIssueDate || ''
    const db = b.cftIssueDate || ''
    return db.localeCompare(da)
  })

  return c.json({
    totalHits: results.length,
    items: results,
    errors: Object.keys(errors).length > 0 ? errors : undefined,
  })
})

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

    // 検索対象フィールドとAND検索フィルタリング
    if (query && parsed.items) {
      // 検索対象フィールド（カンマ区切り: name, desc, org）
      const searchFields = (c.req.query('searchFields') || 'name').split(',')
      // スペース区切りでAND検索（全角・半角スペース対応）
      const keywords = query.toLowerCase().split(/[\s　]+/).filter(k => k.length > 0)

      parsed.items = (parsed.items as any[]).filter((item: any) => {
        // 検索対象テキストを結合
        const targets: string[] = []
        if (searchFields.includes('name')) targets.push((item.projectName || '').toLowerCase())
        if (searchFields.includes('desc')) targets.push((item.projectDescription || '').toLowerCase())
        if (searchFields.includes('org')) targets.push((item.organizationName || '').toLowerCase())
        const combined = targets.join(' ')
        // 全キーワードが含まれていればAND一致
        return keywords.every(kw => combined.includes(kw))
      })
      parsed.totalHits = parsed.items.length
    }

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
// 協会けんぽ 調達情報スクレイピング
// =============================

// 協会けんぽHTMLパーサー
function parseKyoukaikenpoHtml(html: string, sourceLabel: string): any[] {
  const items: any[] = []

  // <h3>タグでセクションを分割（一般競争入札・見積競争・企画競争・公募など）
  const sectionRegex = /<h3[^>]*>([\s\S]*?)<\/h3>([\s\S]*?)(?=<h3|<h2|$)/gi
  let secMatch
  while ((secMatch = sectionRegex.exec(html)) !== null) {
    const sectionTitle = secMatch[1].replace(/<[^>]+>/g, '').trim()
    const sectionBody = secMatch[2]

    // テーブル行を抽出
    const rowRegex = /<tr[^>]*>([\s\S]*?)<\/tr>/gi
    let rowMatch
    while ((rowMatch = rowRegex.exec(sectionBody)) !== null) {
      const row = rowMatch[1]
      // td要素を抽出
      const tds: string[] = []
      const tdRegex = /<td[^>]*>([\s\S]*?)<\/td>/gi
      let tdMatch
      while ((tdMatch = tdRegex.exec(row)) !== null) {
        tds.push(tdMatch[1])
      }
      if (tds.length < 2) continue

      // 公告日セル（1列目）
      const dateRaw = tds[0].replace(/<[^>]+>/g, '').trim()

      // 案件名セル（2列目）からリンクと件名を抽出
      const linkRegex = /<a[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/gi
      let linkMatch
      while ((linkMatch = linkRegex.exec(tds[1])) !== null) {
        const href = linkMatch[1]
        const name = linkMatch[2].replace(/<[^>]+>/g, '').trim()
        if (!name) continue

        // 絶対URLに変換
        const url = href.startsWith('http') ? href : `https://www.kyoukaikenpo.or.jp${href}`

        // 和暦→西暦変換
        const isoDate = wareki2iso(dateRaw)

        items.push({
          resultId: `kkp-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
          projectName: name,
          organizationName: '全国健康保険協会（協会けんぽ）',
          procedureType: sectionTitle,
          cftIssueDate: isoDate,
          url: url,
          category: '役務',
          prefectureName: '東京都',
          source: sourceLabel,
          attachments: [{ name: '公告PDF', uri: url }],
        })
      }
    }
  }
  return items
}

// 和暦→ISO8601 変換
function wareki2iso(wareki: string): string {
  // スペースや改行を正規化
  const s = wareki.replace(/\s+/g, '')
  // 例: 令和08年03月23日 or 令和8年4月20日 → 2026-03-23
  const m = s.match(/令和(\d{1,2})年(\d{1,2})月(\d{1,2})日/)
  if (m) {
    const year = 2018 + parseInt(m[1])
    const month = m[2].padStart(2, '0')
    const day = m[3].padStart(2, '0')
    return `${year}-${month}-${day}T00:00:00+09:00`
  }
  const m2 = s.match(/平成(\d{1,2})年(\d{1,2})月(\d{1,2})日/)
  if (m2) {
    const year = 1988 + parseInt(m2[1])
    const month = m2[2].padStart(2, '0')
    const day = m2[3].padStart(2, '0')
    return `${year}-${month}-${day}T00:00:00+09:00`
  }
  return wareki
}

// 協会けんぽ 現在公開中の案件
app.get('/api/kyoukaikenpo', async (c) => {
  const archive = c.req.query('archive') || '' // r07, r06, r05 etc.

  try {
    const url = archive
      ? `https://www.kyoukaikenpo.or.jp/disclosure/procurement/${archive}`
      : 'https://www.kyoukaikenpo.or.jp/disclosure/procurement/'

    const res = await fetch(url, {
      headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' },
    })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    const html = await res.text()

    const label = archive ? `協会けんぽ (${archive})` : '協会けんぽ (公開中)'
    const items = parseKyoukaikenpoHtml(html, label)

    // キーワードフィルタ（AND検索・検索対象選択対応）
    const query = c.req.query('query') || ''
    const searchFields = (c.req.query('searchFields') || 'name').split(',')
    const filtered = query
      ? filterItemsByKeyword(items, query, searchFields)
      : items

    return c.json({ totalHits: filtered.length, items: filtered, source: '協会けんぽ' })
  } catch (e) {
    return c.json({ error: String(e), totalHits: 0, items: [] }, 500)
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
// 共通キーワードフィルタ（AND検索・検索対象選択対応）
// searchFields: ['name', 'desc', 'org'] の組み合わせ
// query: スペース区切りでAND検索
// =============================
function filterItemsByKeyword(items: any[], query: string, searchFields: string[]): any[] {
  if (!query) return items
  const keywords = query.toLowerCase().split(/[\s　]+/).filter(k => k.length > 0)
  return items.filter(item => {
    const targets: string[] = []
    if (searchFields.includes('name')) targets.push((item.projectName || '').toLowerCase())
    if (searchFields.includes('desc')) targets.push((item.projectDescription || '').toLowerCase())
    if (searchFields.includes('org')) targets.push((item.organizationName || '').toLowerCase())
    const combined = targets.join(' ')
    return keywords.every(kw => combined.includes(kw))
  })
}

// =============================
// 防衛省（内局）スクレイパー
// URL: https://www.mod.go.jp/j/budget/chotatsu/naikyoku/mitsumori/index.html
// 構造: テーブル（番号/種別/調達番号/件名/見積依頼書公開日/見積書提出期限/...）
// =============================
function scrapeMod(html: string, baseUrl: string): any[] {
  const items: any[] = []
  try {
    // テーブル行を抽出 <tr>...</tr>
    const trMatches = html.matchAll(/<tr[^>]*>([\s\S]*?)<\/tr>/gi)
    for (const trMatch of trMatches) {
      const row = trMatch[1]
      // tdを抽出
      const tdMatches = [...row.matchAll(/<td[^>]*>([\s\S]*?)<\/td>/gi)]
      if (tdMatches.length < 4) continue
      const cols = tdMatches.map(m => {
        const text = m[1].replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim()
        return text
      })
      // 件名が入るのは4列目(index=3)
      const projectName = cols[3] || ''
      if (!projectName || projectName === '件名') continue

      // 見積依頼書公開日: 5列目(index=4)
      const dateStr = cols[4] || ''
      const isoDate = wareki2iso(dateStr)

      // 見積書提出期限: 6列目(index=5)
      const deadline = cols[5] || ''
      const isoDeadline = wareki2iso(deadline)

      // PDFリンク抽出
      const pdfMatches = [...trMatch[1].matchAll(/href="([^"]*\.pdf[^"]*)"/gi)]
      const pdfUrl = pdfMatches.length > 0
        ? (pdfMatches[0][1].startsWith('http') ? pdfMatches[0][1] : 'https://www.mod.go.jp' + pdfMatches[0][1])
        : baseUrl
      const attachments = pdfMatches.map(m => ({
        name: 'PDF',
        uri: m[1].startsWith('http') ? m[1] : 'https://www.mod.go.jp' + m[1]
      }))

      const kind = cols[1] || ''
      items.push({
        resultId: `mod-naikyoku-${cols[0] || ''}-${isoDate}`,
        projectName,
        organizationName: '防衛省（内局）',
        procedureType: '見積合わせ（随意契約）',
        category: kind.includes('物品') ? '物品' : '役務',
        cftIssueDate: isoDate,
        tenderDeadline: isoDeadline,
        url: pdfUrl,
        prefectureName: '東京都',
        source: '防衛省（内局）',
        attachments,
      })
    }
  } catch (e) {
    // ignore
  }
  return items
}

// wareki2iso は既に定義済み（共通関数）

// 防衛省情報本部スクレイパー
// URL: https://www.mod.go.jp/dih/supply/open-r8.html
// 構造: テーブル（番号/見積期限/件名/履行期限/仕様書PDF/詳細PDF）
function scrapeModDih(html: string, baseUrl: string): any[] {
  const items: any[] = []
  try {
    const trMatches = html.matchAll(/<tr[^>]*>([\s\S]*?)<\/tr>/gi)
    for (const trMatch of trMatches) {
      const row = trMatch[1]
      const tdMatches = [...row.matchAll(/<td[^>]*>([\s\S]*?)<\/td>/gi)]
      if (tdMatches.length < 3) continue
      const cols = tdMatches.map(m => {
        const text = m[1].replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim()
        return text
      })

      // 見積期限: 2列目(index=1)
      const deadlineStr = cols[1] || ''
      const isoDeadline = wareki2iso(deadlineStr.split('(')[0].trim())

      // 件名リンクのテキスト: 3列目(index=2)
      // aタグのテキストを取得
      const nameMatch = tdMatches[2]?.[1].match(/<a[^>]*>([\s\S]*?)<\/a>/i)
      const projectName = nameMatch
        ? nameMatch[1].replace(/<[^>]+>/g, '').replace(/\(PDFを別タブで開く\)/g, '').trim()
        : cols[2] || ''
      if (!projectName || projectName === '件名') continue

      // 件名のPDFリンク
      const mainPdfMatch = tdMatches[2]?.[1].match(/href="([^"]*\.pdf[^"]*)"/i)
      const mainPdfUrl = mainPdfMatch
        ? (mainPdfMatch[1].startsWith('http') ? mainPdfMatch[1] : 'https://www.mod.go.jp' + mainPdfMatch[1])
        : baseUrl

      // 添付（仕様書/詳細PDF）
      const allPdfMatches = [...trMatch[1].matchAll(/href="([^"]*\.(?:pdf|xlsx)[^"]*)"/gi)]
      const attachments = allPdfMatches.map(m => ({
        name: m[1].includes('xlsx') ? '見積書等' : 'PDF',
        uri: m[1].startsWith('http') ? m[1] : 'https://www.mod.go.jp' + m[1]
      }))

      // 番号: 1列目(index=0)
      const num = cols[0] || ''

      items.push({
        resultId: `mod-dih-${num}-${isoDeadline}`,
        projectName,
        organizationName: '防衛省情報本部',
        procedureType: '見積合わせ（随意契約）',
        category: '役務',
        cftIssueDate: isoDeadline,
        tenderDeadline: isoDeadline,
        url: mainPdfUrl,
        prefectureName: '東京都',
        source: '防衛省情報本部',
        attachments,
      })
    }
  } catch (e) {
    // ignore
  }
  return items
}

// =============================
// 防衛省（内局）APIエンドポイント
// =============================
app.get('/api/mod', async (c) => {
  const query = c.req.query('query') || ''
  const searchFields = (c.req.query('searchFields') || 'name').split(',')
  const url = 'https://www.mod.go.jp/j/budget/chotatsu/naikyoku/mitsumori/index.html'
  try {
    const res = await fetch(url, { headers: { 'User-Agent': 'BidSearchApp/1.0' } })
    const html = await res.text()
    let items = scrapeMod(html, url)
    if (query) items = filterItemsByKeyword(items, query, searchFields)
    return c.json({ totalHits: items.length, items, source: '防衛省（内局）' })
  } catch (e) {
    return c.json({ error: String(e), totalHits: 0, items: [] }, 500)
  }
})

// =============================
// 防衛省情報本部APIエンドポイント
// =============================
app.get('/api/mod-dih', async (c) => {
  const query = c.req.query('query') || ''
  const searchFields = (c.req.query('searchFields') || 'name').split(',')
  const url = 'https://www.mod.go.jp/dih/supply/open-r8.html'
  try {
    const res = await fetch(url, { headers: { 'User-Agent': 'BidSearchApp/1.0' } })
    const html = await res.text()
    let items = scrapeModDih(html, url)
    if (query) items = filterItemsByKeyword(items, query, searchFields)
    return c.json({ totalHits: items.length, items, source: '防衛省情報本部' })
  } catch (e) {
    return c.json({ error: String(e), totalHits: 0, items: [] }, 500)
  }
})

// =============================
// 金融庁 スクレイピングAPI
// URL: https://www.fsa.go.jp/choutatu/choutatu_j/nyusatu_menu.html
// 構造: <table><thead><th>公示日</th><th>案件名</th></thead><tbody>
//       <tr><th scope="row"><a href="xxx.pdf">令和X年X月X日付公告</a></th><td>案件名</td></tr>
// =============================
function scrapeFsa(html: string): any[] {
  const items: any[] = []
  // 8つのテーブルから全案件を抽出（入札公告・企画競争・公募・随意契約など）
  const tableRegex = /<table[^>]*>([\s\S]*?)<\/table>/gi
  let tMatch
  const sectionTitles: string[] = []
  // h3タグからセクションタイトルを取得（テーブルと1対1対応）
  const h3Regex = /<h3[^>]*>([\s\S]*?)<\/h3>/gi
  let h3M
  while ((h3M = h3Regex.exec(html)) !== null) {
    const t = h3M[1].replace(/<[^>]+>/g, '').trim()
    if (t) sectionTitles.push(t)
  }
  let tableIdx = 0
  while ((tMatch = tableRegex.exec(html)) !== null) {
    const tableHtml = tMatch[1]
    const procedureType = sectionTitles[tableIdx] || '入札公告'
    tableIdx++
    // 落札者公示・随意契約などはスキップ（入札公告・企画競争・公募のみ）
    if (procedureType.includes('落札') || procedureType.includes('随意')) continue
    const rowRegex = /<tr[^>]*>([\s\S]*?)<\/tr>/gi
    let rowMatch
    while ((rowMatch = rowRegex.exec(tableHtml)) !== null) {
      const row = rowMatch[1]
      // th[scope=row] から日付テキスト・PDFリンクを取得
      const thMatch = row.match(/<th[^>]*scope=["']?row["']?[^>]*>([\s\S]*?)<\/th>/i)
      if (!thMatch) continue
      const thHtml = thMatch[1]
      const aMatch = thHtml.match(/<a[^>]+href="([^"]*)"[^>]*>([\s\S]*?)<\/a>/i)
      if (!aMatch) continue
      let pdfPath = aMatch[1]
      const dateText = aMatch[2].replace(/<[^>]+>/g, '').trim()
      // 日付テキスト例: "令和８年４月15日付公告" → ISO変換
      // 全角数字→半角変換してからwareki2iso
      const dateNorm = dateText.replace(/[０-９]/g, s => String.fromCharCode(s.charCodeAt(0) - 0xFEE0))
      const cftIssueDate = wareki2iso(dateNorm)
      // td から案件名
      const tdMatch = row.match(/<td[^>]*>([\s\S]*?)<\/td>/i)
      if (!tdMatch) continue
      const projectName = tdMatch[1].replace(/<[^>]+>/g, '').trim()
      if (!projectName) continue
      // PDF URLを絶対URLに変換
      if (!pdfPath.startsWith('http')) {
        pdfPath = 'https://www.fsa.go.jp' + (pdfPath.startsWith('/') ? pdfPath : '/choutatu/choutatu_j/' + pdfPath)
      }
      const resultId = `fsa-${cftIssueDate}-${projectName.slice(0, 20)}`
      items.push({
        resultId,
        source: 'fsa',
        organizationName: '金融庁',
        projectName,
        procedureType,
        cftIssueDate,
        url: pdfPath,
        prefectureName: '東京都',
        category: '役務',
        attachments: [{ name: '公告PDF', url: pdfPath }],
      })
    }
  }
  return items
}

app.get('/api/fsa', async (c) => {
  const keyword = c.req.query('keyword') || c.req.query('query') || ''
  const searchFields = (c.req.query('searchFields') || 'name').split(',')
  try {
    const res = await fetch('https://www.fsa.go.jp/choutatu/choutatu_j/nyusatu_menu.html', {
      headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' }
    })
    if (!res.ok) return c.json({ error: `取得失敗: ${res.status}` }, 500)
    const html = await res.text()
    let items = scrapeFsa(html)
    if (keyword) items = filterItemsByKeyword(items, keyword, searchFields)
    return c.json({ source: '金融庁', totalHits: items.length, items })
  } catch (e) {
    return c.json({ error: String(e) }, 500)
  }
})

// =============================
// フロントエンド HTML配信（APIルートより後に定義）
// =============================
// ※ notify-check / notify-status は renderHTML() 関数定義後、
//   app.get('/') より前に登録するため下部に移動済み

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

<!-- ログインオーバーレイ -->
<div id="login-overlay" class="fixed inset-0 z-50 flex items-center justify-center hidden" style="background: linear-gradient(135deg, #1e3a5f 0%, #2563eb 100%);">
  <div class="bg-white rounded-2xl shadow-2xl w-full max-w-sm mx-4 overflow-hidden">
    <div class="gradient-bg p-8 text-center">
      <div class="w-16 h-16 bg-white/20 rounded-2xl flex items-center justify-center mx-auto mb-4">
        <i class="fas fa-gavel text-white text-3xl"></i>
      </div>
      <h1 class="text-2xl font-bold text-white">入札DX</h1>
      <p class="text-blue-200 text-sm mt-1">官公需情報検索システム</p>
    </div>
    <div class="p-8">
      <h2 class="text-lg font-bold text-gray-800 mb-6 text-center">ログイン</h2>
      <div id="login-error" class="hidden mb-4 bg-red-50 border border-red-200 text-red-600 text-sm rounded-xl px-4 py-3">
        <i class="fas fa-exclamation-circle mr-2"></i><span id="login-error-msg"></span>
      </div>
      <div class="mb-4">
        <label class="block text-xs font-medium text-gray-600 mb-1">パスワード</label>
        <input
          id="login-password"
          type="password"
          placeholder="パスワードを入力"
          class="w-full px-4 py-3 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-blue-300"
          onkeypress="if(event.key==='Enter') doLogin()"
        >
      </div>
      <button onclick="doLogin()" id="login-btn" class="w-full btn-primary text-white py-3 rounded-xl font-medium text-sm shadow-md">
        <i class="fas fa-sign-in-alt mr-2"></i>ログイン
      </button>
    </div>
  </div>
</div>

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
  <nav class="flex-1 p-4 space-y-1 overflow-y-auto" style="scrollbar-width:thin;scrollbar-color:rgba(255,255,255,0.2) transparent;">
    <a href="#" onclick="showPage('dashboard')" class="sidebar-link active flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-dashboard">
      <i class="fas fa-th-large w-4"></i> ダッシュボード
    </a>
    <a href="#" onclick="showPage('search')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-search">
      <i class="fas fa-search w-4"></i> 案件検索
    </a>
    <a href="#" onclick="showPage('new')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-new">
      <i class="fas fa-clock w-4"></i> 新着案件
    </a>
    <a href="#" onclick="showPage('construction')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-construction">
      <i class="fas fa-hard-hat w-4"></i> 工事案件
    </a>
    <a href="#" onclick="showPage('goods')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-goods">
      <i class="fas fa-box w-4"></i> 物品案件
    </a>
    <a href="#" onclick="showPage('service')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-service">
      <i class="fas fa-concierge-bell w-4"></i> 役務案件
    </a>
    <div class="border-t border-white/20 my-2"></div>
    <p class="text-xs text-blue-300 px-4 py-1 font-medium uppercase tracking-wider">一括検索</p>
    <a href="#" onclick="showPage('all')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-all">
      <i class="fas fa-layer-group w-4"></i> 全ソース一括検索
    </a>
    <div class="border-t border-white/20 my-2"></div>
    <p class="text-xs text-blue-300 px-4 py-1 font-medium uppercase tracking-wider">独法・研究機関</p>
    <a href="#" onclick="showPage('jeed')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-jeed">
      <i class="fas fa-hands-helping w-4"></i> JEED雇用支援機構
    </a>
    <a href="#" onclick="showPage('uitec')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-uitec">
      <i class="fas fa-graduation-cap w-4"></i> 職業能力開発大学校
    </a>
    <a href="#" onclick="showPage('ipa')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-ipa">
      <i class="fas fa-microchip w-4"></i> IPA 情報処理推進機構
    </a>
    <a href="#" onclick="showPage('bosai')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-bosai">
      <i class="fas fa-hard-hat w-4"></i> 防災科学技術研究所
    </a>
    <div class="border-t border-white/20 my-2"></div>
    <p class="text-xs text-blue-300 px-4 py-1 font-medium uppercase tracking-wider">社会保険・金融</p>
    <a href="#" onclick="showPage('kyoukaikenpo')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-kyoukaikenpo">
      <i class="fas fa-heartbeat w-4"></i> 協会けんぽ
    </a>
    <a href="#" onclick="showPage('pfa')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-pfa">
      <i class="fas fa-piggy-bank w-4"></i> 企業年金連合会
    </a>
    <a href="#" onclick="showPage('jfc')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-jfc">
      <i class="fas fa-university w-4"></i> 日本政策金融公庫
    </a>
    <a href="#" onclick="showPage('fsa')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-fsa">
      <i class="fas fa-chart-line w-4"></i> 金融庁
    </a>
    <div class="border-t border-white/20 my-2"></div>
    <p class="text-xs text-blue-300 px-4 py-1 font-medium uppercase tracking-wider">防衛省系</p>
    <a href="#" onclick="showPage('mod')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-mod">
      <i class="fas fa-shield-alt w-4"></i> 防衛省（内局）
    </a>
    <a href="#" onclick="showPage('mod-dih')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-mod-dih">
      <i class="fas fa-satellite-dish w-4"></i> 防衛省情報本部
    </a>
    <a href="#" onclick="window.open('https://www.mod.go.jp/atla/data/info/ny_honbu/ippan.html','_blank')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-mod-atla">
      <i class="fas fa-cogs w-4"></i> 防衛装備庁 <i class="fas fa-external-link-alt ml-auto text-xs opacity-60"></i>
    </a>
    <a href="#" onclick="window.open('https://www.mod.go.jp/gsdf/tercom/procurement.html','_blank')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-mod-gsdf">
      <i class="fas fa-user-shield w-4"></i> 陸上自衛隊 <i class="fas fa-external-link-alt ml-auto text-xs opacity-60"></i>
    </a>
    <div class="border-t border-white/20 my-2"></div>
    <p class="text-xs text-blue-300 px-4 py-1 font-medium uppercase tracking-wider">地方自治体</p>
    <a href="#" onclick="showPage('osaka')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-osaka">
      <i class="fas fa-city w-4"></i> 大阪市デジタル統括室
    </a>
    <a href="#" onclick="showPage('hokkaido')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-hokkaido">
      <i class="fas fa-snowflake w-4"></i> 北海道 情報政策課
    </a>
    <a href="#" onclick="showPage('imabari')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-imabari">
      <i class="fas fa-map-marker-alt w-4"></i> 今治市 産業振興課
    </a>
    <a href="#" onclick="showPage('nagano')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-nagano">
      <i class="fas fa-mountain w-4"></i> 長野県 営業局
    </a>
    <a href="#" onclick="window.open('https://www.city.setagaya.lg.jp/','_blank')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-setagaya">
      <i class="fas fa-building w-4"></i> 世田谷区 <i class="fas fa-external-link-alt ml-auto text-xs opacity-60"></i>
    </a>
    <a href="#" onclick="window.open('https://www.city.kitakyushu.lg.jp/contents/division337list.html','_blank')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-kitakyushu">
      <i class="fas fa-industry w-4"></i> 北九州市DX・AI戦略室 <i class="fas fa-external-link-alt ml-auto text-xs opacity-60"></i>
    </a>
    <a href="#" onclick="window.open('https://www.city.ota.tokyo.jp/','_blank')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-ota">
      <i class="fas fa-map w-4"></i> 大田区 <i class="fas fa-external-link-alt ml-auto text-xs opacity-60"></i>
    </a>
    <a href="#" onclick="window.open('https://www.city.itabashi.tokyo.jp/','_blank')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-itabashi">
      <i class="fas fa-landmark w-4"></i> 板橋区 <i class="fas fa-external-link-alt ml-auto text-xs opacity-60"></i>
    </a>
    <a href="#" onclick="window.open('https://www.city.suginami.tokyo.jp/nyuusatsuoshirase/proposal/index.html','_blank')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-suginami">
      <i class="fas fa-file-contract w-4"></i> 杉並区プロポーザル <i class="fas fa-external-link-alt ml-auto text-xs opacity-60"></i>
    </a>
    <a href="#" onclick="window.open('https://www.city.kumamoto.jp/','_blank')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-kumamoto">
      <i class="fas fa-torii-gate w-4"></i> 熊本市 <i class="fas fa-external-link-alt ml-auto text-xs opacity-60"></i>
    </a>
    <a href="#" onclick="window.open('https://www.pref.kagawa.lg.jp/','_blank')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-kagawa">
      <i class="fas fa-water w-4"></i> 香川県 <i class="fas fa-external-link-alt ml-auto text-xs opacity-60"></i>
    </a>
    <a href="#" onclick="window.open('https://www.pref.shizuoka.jp/','_blank')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-shizuoka">
      <i class="fas fa-leaf w-4"></i> 静岡県 <i class="fas fa-external-link-alt ml-auto text-xs opacity-60"></i>
    </a>
    <a href="#" onclick="window.open('https://www.nilim.go.jp/lab/adg/koukoku.htm','_blank')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-nilim">
      <i class="fas fa-road w-4"></i> 国土技術政策総合研究所 <i class="fas fa-external-link-alt ml-auto text-xs opacity-60"></i>
    </a>
    <div class="border-t border-white/20 my-2"></div>
    <a href="#" onclick="showPage('bookmark')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-bookmark">
      <i class="fas fa-star w-4"></i> ブックマーク
      <span id="bookmark-count-badge" class="ml-auto bg-yellow-400 text-yellow-900 text-xs font-bold px-2 py-0.5 rounded-full hidden">0</span>
    </a>
    <a href="#" onclick="showPage('notify')" class="sidebar-link flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm" id="nav-notify">
      <i class="fas fa-bell w-4"></i> メール通知設定
    </a>
  </nav>
  <div class="p-4 border-t border-white/20">
    <button onclick="doLogout()" class="w-full flex items-center justify-center gap-2 text-xs text-blue-200 hover:text-white hover:bg-white/10 rounded-lg py-2 px-3 transition-all">
      <i class="fas fa-sign-out-alt"></i> ログアウト
    </button>
    <p class="text-xs text-blue-300 text-center mt-2">全20機関 統合検索対応</p>
  </div>
</div>

<!-- メインコンテンツ -->
<div class="ml-64 min-h-screen">

  <!-- ヘッダー -->
  <header class="bg-white border-b border-gray-200 px-8 py-4 sticky top-0 z-20 shadow-sm">
    <div class="flex items-center justify-between">
      <div>
        <h2 id="page-title" class="text-xl font-bold text-gray-800">ダッシュボード</h2>
        <p class="text-xs text-gray-500 mt-0.5" id="page-subtitle">官公需情報ポータルサイト・協会けんぽ・企業年金連合会のリアルタイムデータ</p>
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
        <!-- 検索対象・AND検索オプション -->
        <div class="bg-gray-50 rounded-xl px-4 py-3 mb-4 flex flex-wrap items-center gap-4">
          <div class="flex items-center gap-1 text-xs font-medium text-gray-600">
            <i class="fas fa-sliders-h text-blue-500 mr-1"></i>検索対象：
          </div>
          <label class="flex items-center gap-1.5 text-xs text-gray-700 cursor-pointer">
            <input type="checkbox" id="sf-name" checked class="accent-blue-500"> 案件名
          </label>
          <label class="flex items-center gap-1.5 text-xs text-gray-700 cursor-pointer">
            <input type="checkbox" id="sf-desc" class="accent-blue-500"> 説明文
            <span class="text-gray-400">（官公需ポータルのみ）</span>
          </label>
          <label class="flex items-center gap-1.5 text-xs text-gray-700 cursor-pointer">
            <input type="checkbox" id="sf-org" class="accent-blue-500"> 機関名
          </label>
          <div class="border-l border-gray-300 pl-4 flex items-center gap-1.5 text-xs text-gray-500">
            <i class="fas fa-info-circle text-blue-400"></i>
            スペース区切りで<strong class="text-gray-700">AND検索</strong>（例：「動画制作 東京都」）
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

    <!-- 協会けんぽ専用ページ -->
    <div id="page-kyoukaikenpo" class="page-content hidden">
      <!-- ヘッダーカード -->
      <div class="bg-gradient-to-br from-rose-50 to-pink-50 border border-rose-100 rounded-2xl p-6 mb-6">
        <div class="flex items-start gap-4">
          <div class="w-14 h-14 bg-rose-100 rounded-2xl flex items-center justify-center flex-shrink-0">
            <i class="fas fa-heartbeat text-rose-600 text-2xl"></i>
          </div>
          <div class="flex-1">
            <h3 class="text-lg font-bold text-gray-800 mb-1">全国健康保険協会（協会けんぽ）調達情報</h3>
            <p class="text-sm text-gray-600 mb-3">協会けんぽ公式サイトの調達情報を直接取得します。一般競争入札・見積競争・企画競争・公募の案件を確認できます。</p>
            <div class="flex flex-wrap gap-2">
              <a href="https://www.kyoukaikenpo.or.jp/disclosure/procurement/" target="_blank"
                 class="text-xs bg-white border border-rose-200 text-rose-600 px-3 py-1.5 rounded-lg hover:bg-rose-50 flex items-center gap-1">
                <i class="fas fa-external-link-alt"></i> 公式サイトを開く
              </a>
            </div>
          </div>
        </div>
      </div>

      <!-- フィルター -->
      <div class="bg-white rounded-2xl shadow-sm border border-gray-100 p-5 mb-6">
        <div class="flex flex-wrap items-end gap-4">
          <div class="flex-1 min-w-48">
            <label class="block text-xs font-medium text-gray-600 mb-1">キーワード</label>
            <input id="kkp-query" type="text" placeholder="案件名で絞り込み..."
              class="w-full px-3 py-2.5 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-rose-300"
              onkeypress="if(event.key==='Enter') loadKyoukaikenpo()">
          </div>
          <div>
            <label class="block text-xs font-medium text-gray-600 mb-1">年度</label>
            <select id="kkp-archive" class="px-3 py-2.5 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-rose-300">
              <option value="">令和8年度（公開中）</option>
              <option value="r07">令和7年度（終了分）</option>
              <option value="r06">令和6年度（終了分）</option>
              <option value="r05">令和5年度（終了分）</option>
            </select>
          </div>
          <button onclick="loadKyoukaikenpo()"
            class="px-6 py-2.5 rounded-xl font-medium text-sm text-white shadow-md flex items-center gap-2"
            style="background: linear-gradient(135deg, #e11d48, #be123c);">
            <i class="fas fa-search"></i> 取得する
          </button>
        </div>
      </div>

      <div id="kkp-result-area"></div>
    </div>

    <!-- 企業年金連合会専用ページ -->
    <div id="page-pfa" class="page-content hidden">
      <div class="bg-gradient-to-br from-amber-50 to-yellow-50 border border-amber-100 rounded-2xl p-6 mb-6">
        <div class="flex items-start gap-4">
          <div class="w-14 h-14 bg-amber-100 rounded-2xl flex items-center justify-center flex-shrink-0">
            <i class="fas fa-piggy-bank text-amber-600 text-2xl"></i>
          </div>
          <div class="flex-1">
            <h3 class="text-lg font-bold text-gray-800 mb-1">企業年金連合会 調達情報</h3>
            <p class="text-sm text-gray-600 mb-3">企業年金連合会公式サイトの調達情報（入札・競争）を直接取得します。</p>
            <div class="flex flex-wrap gap-2">
              <a href="https://www.pfa.or.jp/chotatsu/ichiran/index.html" target="_blank"
                 class="text-xs bg-white border border-amber-200 text-amber-600 px-3 py-1.5 rounded-lg hover:bg-amber-50 flex items-center gap-1">
                <i class="fas fa-external-link-alt"></i> 公式サイトを開く
              </a>
            </div>
          </div>
        </div>
      </div>
      <div class="bg-white rounded-2xl shadow-sm border border-gray-100 p-5 mb-6">
        <div class="flex flex-wrap items-end gap-4">
          <div class="flex-1 min-w-48">
            <label class="block text-xs font-medium text-gray-600 mb-1">キーワード</label>
            <input id="pfa-query" type="text" placeholder="案件名で絞り込み..."
              class="w-full px-3 py-2.5 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-amber-300"
              onkeypress="if(event.key==='Enter') loadPfa()">
          </div>
          <button onclick="loadPfa()"
            class="px-6 py-2.5 rounded-xl font-medium text-sm text-white shadow-md flex items-center gap-2"
            style="background: linear-gradient(135deg, #d97706, #b45309);">
            <i class="fas fa-search"></i> 取得する
          </button>
        </div>
      </div>
      <div id="pfa-result-area"></div>
    </div>

    <!-- JEED（高齢・障害・求職者雇用支援機構）ページ -->
    <div id="page-jeed" class="page-content hidden">
      <div class="bg-gradient-to-br from-teal-50 to-green-50 border border-teal-100 rounded-2xl p-6 mb-6">
        <div class="flex items-start gap-4">
          <div class="w-14 h-14 bg-teal-100 rounded-2xl flex items-center justify-center flex-shrink-0">
            <i class="fas fa-hands-helping text-teal-600 text-2xl"></i>
          </div>
          <div class="flex-1">
            <h3 class="text-lg font-bold text-gray-800 mb-1">独立行政法人高齢・障害・求職者雇用支援機構 調達情報</h3>
            <p class="text-sm text-gray-600 mb-3">JEEDの入札公告（物品製造・販売・役務提供等）を直接取得します。</p>
            <div class="flex flex-wrap gap-2">
              <a href="https://www.jeed.go.jp/jeed/information/honbu/chotatsu_buppin.html" target="_blank"
                 class="text-xs bg-white border border-teal-200 text-teal-600 px-3 py-1.5 rounded-lg hover:bg-teal-50 flex items-center gap-1">
                <i class="fas fa-external-link-alt"></i> 公式サイトを開く
              </a>
            </div>
          </div>
        </div>
      </div>
      <div class="bg-white rounded-2xl shadow-sm border border-gray-100 p-5 mb-6">
        <div class="flex flex-wrap items-end gap-4">
          <div class="flex-1 min-w-48">
            <label class="block text-xs font-medium text-gray-600 mb-1">キーワード</label>
            <input id="jeed-query" type="text" placeholder="案件名で絞り込み..."
              class="w-full px-3 py-2.5 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-teal-300"
              onkeypress="if(event.key==='Enter') loadJeed()">
          </div>
          <button onclick="loadJeed()"
            class="px-6 py-2.5 rounded-xl font-medium text-sm text-white shadow-md flex items-center gap-2"
            style="background: linear-gradient(135deg, #0d9488, #0f766e);">
            <i class="fas fa-search"></i> 取得する
          </button>
        </div>
      </div>
      <div id="jeed-result-area"></div>
    </div>

    <!-- JFC（日本政策金融公庫）ページ -->
    <div id="page-jfc" class="page-content hidden">
      <div class="bg-gradient-to-br from-indigo-50 to-blue-50 border border-indigo-100 rounded-2xl p-6 mb-6">
        <div class="flex items-start gap-4">
          <div class="w-14 h-14 bg-indigo-100 rounded-2xl flex items-center justify-center flex-shrink-0">
            <i class="fas fa-university text-indigo-600 text-2xl"></i>
          </div>
          <div class="flex-1">
            <h3 class="text-lg font-bold text-gray-800 mb-1">株式会社日本政策金融公庫 調達情報</h3>
            <p class="text-sm text-gray-600 mb-3">日本政策金融公庫の入札情報（物品役務等）を直接取得します。</p>
            <div class="flex flex-wrap gap-2">
              <a href="https://www.jfc.go.jp/n/supply/bid_1.html" target="_blank"
                 class="text-xs bg-white border border-indigo-200 text-indigo-600 px-3 py-1.5 rounded-lg hover:bg-indigo-50 flex items-center gap-1">
                <i class="fas fa-external-link-alt"></i> 公式サイトを開く
              </a>
            </div>
          </div>
        </div>
      </div>
      <div class="bg-white rounded-2xl shadow-sm border border-gray-100 p-5 mb-6">
        <div class="flex flex-wrap items-end gap-4">
          <div class="flex-1 min-w-48">
            <label class="block text-xs font-medium text-gray-600 mb-1">キーワード</label>
            <input id="jfc-query" type="text" placeholder="案件名で絞り込み..."
              class="w-full px-3 py-2.5 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-300"
              onkeypress="if(event.key==='Enter') loadJfc()">
          </div>
          <button onclick="loadJfc()"
            class="px-6 py-2.5 rounded-xl font-medium text-sm text-white shadow-md flex items-center gap-2"
            style="background: linear-gradient(135deg, #4f46e5, #4338ca);">
            <i class="fas fa-search"></i> 取得する
          </button>
        </div>
      </div>
      <div id="jfc-result-area"></div>
    </div>

    <!-- IPA（情報処理推進機構）ページ -->
    <div id="page-ipa" class="page-content hidden">
      <div class="bg-gradient-to-br from-sky-50 to-blue-50 border border-sky-100 rounded-2xl p-6 mb-6">
        <div class="flex items-start gap-4">
          <div class="w-14 h-14 bg-sky-100 rounded-2xl flex items-center justify-center flex-shrink-0">
            <i class="fas fa-microchip text-sky-600 text-2xl"></i>
          </div>
          <div class="flex-1">
            <h3 class="text-lg font-bold text-gray-800 mb-1">独立行政法人情報処理推進機構（IPA）調達情報</h3>
            <p class="text-sm text-gray-600 mb-3">情報処理推進機構の入札公告情報を直接取得します。サイバーセキュリティ・DX関連案件が多数あります。</p>
            <div class="flex flex-wrap gap-2">
              <a href="https://www.ipa.go.jp/choutatsu/nyusatsu/index.html" target="_blank"
                 class="text-xs bg-white border border-sky-200 text-sky-600 px-3 py-1.5 rounded-lg hover:bg-sky-50 flex items-center gap-1">
                <i class="fas fa-external-link-alt"></i> 公式サイトを開く
              </a>
            </div>
          </div>
        </div>
      </div>
      <div class="bg-white rounded-2xl shadow-sm border border-gray-100 p-5 mb-6">
        <div class="flex flex-wrap items-end gap-4">
          <div class="flex-1 min-w-48">
            <label class="block text-xs font-medium text-gray-600 mb-1">キーワード</label>
            <input id="ipa-query" type="text" placeholder="案件名で絞り込み..."
              class="w-full px-3 py-2.5 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-sky-300"
              onkeypress="if(event.key==='Enter') loadIpa()">
          </div>
          <button onclick="loadIpa()"
            class="px-6 py-2.5 rounded-xl font-medium text-sm text-white shadow-md flex items-center gap-2"
            style="background: linear-gradient(135deg, #0ea5e9, #0284c7);">
            <i class="fas fa-search"></i> 取得する
          </button>
        </div>
      </div>
      <div id="ipa-result-area"></div>
    </div>

    <!-- 防災科研ページ -->
    <div id="page-bosai" class="page-content hidden">
      <div class="bg-gradient-to-br from-orange-50 to-amber-50 border border-orange-100 rounded-2xl p-6 mb-6">
        <div class="flex items-start gap-4">
          <div class="w-14 h-14 bg-orange-100 rounded-2xl flex items-center justify-center flex-shrink-0">
            <i class="fas fa-hard-hat text-orange-600 text-2xl"></i>
          </div>
          <div class="flex-1">
            <h3 class="text-lg font-bold text-gray-800 mb-1">国立研究開発法人防災科学技術研究所 調達情報</h3>
            <p class="text-sm text-gray-600 mb-3">防災科研の入札公告一覧から調達情報を取得します。防災・観測システム関連案件が多数あります。</p>
            <div class="flex flex-wrap gap-2">
              <a href="https://www.bosai.go.jp/kokai/nyuusatsu/index.html" target="_blank"
                 class="text-xs bg-white border border-orange-200 text-orange-600 px-3 py-1.5 rounded-lg hover:bg-orange-50 flex items-center gap-1">
                <i class="fas fa-external-link-alt"></i> 公式サイトを開く
              </a>
            </div>
          </div>
        </div>
      </div>
      <div class="bg-white rounded-2xl shadow-sm border border-gray-100 p-5 mb-6">
        <div class="flex flex-wrap items-end gap-4">
          <div class="flex-1 min-w-48">
            <label class="block text-xs font-medium text-gray-600 mb-1">キーワード</label>
            <input id="bosai-query" type="text" placeholder="案件名で絞り込み..."
              class="w-full px-3 py-2.5 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-orange-300"
              onkeypress="if(event.key==='Enter') loadBosai()">
          </div>
          <button onclick="loadBosai()"
            class="px-6 py-2.5 rounded-xl font-medium text-sm text-white shadow-md flex items-center gap-2"
            style="background: linear-gradient(135deg, #f97316, #ea580c);">
            <i class="fas fa-search"></i> 取得する
          </button>
        </div>
      </div>
      <div id="bosai-result-area"></div>
    </div>

    <!-- 防衛省（内局）ページ -->
    <div id="page-mod" class="page-content hidden">
      <div class="bg-gradient-to-br from-slate-50 to-gray-100 border border-slate-200 rounded-2xl p-6 mb-6">
        <div class="flex items-start gap-4">
          <div class="w-14 h-14 bg-slate-200 rounded-2xl flex items-center justify-center flex-shrink-0">
            <i class="fas fa-shield-alt text-slate-600 text-2xl"></i>
          </div>
          <div class="flex-1">
            <h3 class="text-lg font-bold text-gray-800 mb-1">防衛省（内局）調達情報</h3>
            <p class="text-sm text-gray-600 mb-3">大臣官房会計課によるオープンカウンター方式の見積依頼情報を取得します。</p>
            <div class="flex flex-wrap gap-2">
              <a href="https://www.mod.go.jp/j/budget/chotatsu/naikyoku/mitsumori/index.html" target="_blank"
                 class="text-xs bg-white border border-slate-300 text-slate-600 px-3 py-1.5 rounded-lg hover:bg-slate-50 flex items-center gap-1">
                <i class="fas fa-external-link-alt"></i> 公式サイトを開く
              </a>
            </div>
          </div>
        </div>
      </div>
      <div class="bg-white rounded-2xl shadow-sm border border-gray-100 p-5 mb-6">
        <div class="flex flex-wrap items-end gap-4">
          <div class="flex-1 min-w-48">
            <label class="block text-xs font-medium text-gray-600 mb-1">キーワード</label>
            <input id="mod-query" type="text" placeholder="案件名で絞り込み..."
              class="w-full px-3 py-2.5 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-slate-300"
              onkeypress="if(event.key==='Enter') loadMod()">
          </div>
          <button onclick="loadMod()"
            class="px-6 py-2.5 rounded-xl font-medium text-sm text-white shadow-md flex items-center gap-2"
            style="background: linear-gradient(135deg, #475569, #334155);">
            <i class="fas fa-search"></i> 取得する
          </button>
        </div>
      </div>
      <div id="mod-result-area"></div>
    </div>

    <!-- 防衛省情報本部ページ -->
    <div id="page-mod-dih" class="page-content hidden">
      <div class="bg-gradient-to-br from-sky-50 to-cyan-50 border border-sky-100 rounded-2xl p-6 mb-6">
        <div class="flex items-start gap-4">
          <div class="w-14 h-14 bg-sky-100 rounded-2xl flex items-center justify-center flex-shrink-0">
            <i class="fas fa-satellite-dish text-sky-600 text-2xl"></i>
          </div>
          <div class="flex-1">
            <h3 class="text-lg font-bold text-gray-800 mb-1">防衛省情報本部 調達情報</h3>
            <p class="text-sm text-gray-600 mb-3">防衛省情報本部（令和8年度）の随意契約見積情報を取得します。</p>
            <div class="flex flex-wrap gap-2">
              <a href="https://www.mod.go.jp/dih/supply/open-r8.html" target="_blank"
                 class="text-xs bg-white border border-sky-200 text-sky-600 px-3 py-1.5 rounded-lg hover:bg-sky-50 flex items-center gap-1">
                <i class="fas fa-external-link-alt"></i> 公式サイトを開く
              </a>
            </div>
          </div>
        </div>
      </div>
      <div class="bg-white rounded-2xl shadow-sm border border-gray-100 p-5 mb-6">
        <div class="flex flex-wrap items-end gap-4">
          <div class="flex-1 min-w-48">
            <label class="block text-xs font-medium text-gray-600 mb-1">キーワード</label>
            <input id="mod-dih-query" type="text" placeholder="案件名で絞り込み..."
              class="w-full px-3 py-2.5 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-sky-300"
              onkeypress="if(event.key==='Enter') loadModDih()">
          </div>
          <button onclick="loadModDih()"
            class="px-6 py-2.5 rounded-xl font-medium text-sm text-white shadow-md flex items-center gap-2"
            style="background: linear-gradient(135deg, #0284c7, #0369a1);">
            <i class="fas fa-search"></i> 取得する
          </button>
        </div>
      </div>
      <div id="mod-dih-result-area"></div>
    </div>

    <!-- UITEC（職業能力開発総合大学校）ページ -->
    <div id="page-uitec" class="page-content hidden">
      <div class="bg-gradient-to-br from-emerald-50 to-teal-50 border border-emerald-100 rounded-2xl p-6 mb-6">
        <div class="flex items-start gap-4">
          <div class="w-14 h-14 bg-emerald-100 rounded-2xl flex items-center justify-center flex-shrink-0">
            <i class="fas fa-graduation-cap text-emerald-600 text-2xl"></i>
          </div>
          <div class="flex-1">
            <h3 class="text-lg font-bold text-gray-800 mb-1">職業能力開発総合大学校（UITEC）調達情報</h3>
            <p class="text-sm text-gray-600 mb-3">独立行政法人高齢・障害・求職者雇用支援機構が設置する大学校の入札・調達情報を取得します。</p>
            <a href="https://www.uitec.jeed.go.jp/topics/tender/fp2ce800000000p3.html" target="_blank"
               class="text-xs bg-white border border-emerald-200 text-emerald-600 px-3 py-1.5 rounded-lg hover:bg-emerald-50 inline-flex items-center gap-1">
              <i class="fas fa-external-link-alt"></i> 公式サイトを開く
            </a>
          </div>
        </div>
      </div>
      <div class="bg-white rounded-2xl shadow-sm border border-gray-100 p-5 mb-6">
        <div class="flex flex-wrap items-end gap-4">
          <div class="flex-1 min-w-48">
            <label class="block text-xs font-medium text-gray-600 mb-1">キーワード</label>
            <input id="uitec-query" type="text" placeholder="案件名で絞り込み..."
              class="w-full px-3 py-2.5 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-emerald-300"
              onkeypress="if(event.key==='Enter') loadUitec()">
          </div>
          <button onclick="loadUitec()"
            class="px-6 py-2.5 rounded-xl font-medium text-sm text-white shadow-md flex items-center gap-2"
            style="background: linear-gradient(135deg, #059669, #047857);">
            <i class="fas fa-search"></i> 取得する
          </button>
        </div>
      </div>
      <div id="uitec-result-area"></div>
    </div>

    <!-- 金融庁ページ -->
    <div id="page-fsa" class="page-content hidden">
      <div class="bg-gradient-to-br from-orange-50 to-amber-50 border border-orange-100 rounded-2xl p-6 mb-6">
        <div class="flex items-start gap-4">
          <div class="w-14 h-14 bg-orange-100 rounded-2xl flex items-center justify-center flex-shrink-0">
            <i class="fas fa-chart-line text-orange-600 text-2xl"></i>
          </div>
          <div class="flex-1">
            <h3 class="text-lg font-bold text-gray-800 mb-1">金融庁 調達情報</h3>
            <p class="text-sm text-gray-600 mb-3">金融庁の入札公告・企画競争・公募公告情報を取得します。</p>
            <a href="https://www.fsa.go.jp/choutatu/choutatu_j/nyusatu_menu.html" target="_blank"
               class="text-xs bg-white border border-orange-200 text-orange-600 px-3 py-1.5 rounded-lg hover:bg-orange-50 inline-flex items-center gap-1">
              <i class="fas fa-external-link-alt"></i> 公式サイトを開く
            </a>
          </div>
        </div>
      </div>
      <div class="bg-white rounded-2xl shadow-sm border border-gray-100 p-5 mb-6">
        <div class="flex flex-wrap items-end gap-4">
          <div class="flex-1 min-w-48">
            <label class="block text-xs font-medium text-gray-600 mb-1">キーワード</label>
            <input id="fsa-query" type="text" placeholder="案件名で絞り込み..."
              class="w-full px-3 py-2.5 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-orange-300"
              onkeypress="if(event.key==='Enter') loadFsa()">
          </div>
          <button onclick="loadFsa()"
            class="px-6 py-2.5 rounded-xl font-medium text-sm text-white shadow-md flex items-center gap-2"
            style="background: linear-gradient(135deg, #d97706, #b45309);">
            <i class="fas fa-search"></i> 取得する
          </button>
        </div>
      </div>
      <div id="fsa-result-area"></div>
    </div>

    <!-- 大阪市デジタル統括室ページ -->
    <div id="page-osaka" class="page-content hidden">
      <div class="bg-gradient-to-br from-pink-50 to-rose-50 border border-pink-100 rounded-2xl p-6 mb-6">
        <div class="flex items-start gap-4">
          <div class="w-14 h-14 bg-pink-100 rounded-2xl flex items-center justify-center flex-shrink-0">
            <i class="fas fa-city text-pink-600 text-2xl"></i>
          </div>
          <div class="flex-1">
            <h3 class="text-lg font-bold text-gray-800 mb-1">大阪市デジタル統括室 調達情報</h3>
            <p class="text-sm text-gray-600 mb-3">大阪市デジタル統括室が発注する業務委託・入札案件を取得します。</p>
            <a href="https://www.city.osaka.lg.jp/templates/gyomuitaku_nyusatsuanken/98-Curr.html" target="_blank"
               class="text-xs bg-white border border-pink-200 text-pink-600 px-3 py-1.5 rounded-lg hover:bg-pink-50 inline-flex items-center gap-1">
              <i class="fas fa-external-link-alt"></i> 公式サイトを開く
            </a>
          </div>
        </div>
      </div>
      <div class="bg-white rounded-2xl shadow-sm border border-gray-100 p-5 mb-6">
        <div class="flex flex-wrap items-end gap-4">
          <div class="flex-1 min-w-48">
            <label class="block text-xs font-medium text-gray-600 mb-1">キーワード</label>
            <input id="osaka-query" type="text" placeholder="案件名で絞り込み..."
              class="w-full px-3 py-2.5 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-pink-300"
              onkeypress="if(event.key==='Enter') loadOsaka()">
          </div>
          <button onclick="loadOsaka()"
            class="px-6 py-2.5 rounded-xl font-medium text-sm text-white shadow-md flex items-center gap-2"
            style="background: linear-gradient(135deg, #db2777, #be185d);">
            <i class="fas fa-search"></i> 取得する
          </button>
        </div>
      </div>
      <div id="osaka-result-area"></div>
    </div>

    <!-- 北海道情報政策課ページ -->
    <div id="page-hokkaido" class="page-content hidden">
      <div class="bg-gradient-to-br from-sky-50 to-blue-50 border border-sky-100 rounded-2xl p-6 mb-6">
        <div class="flex items-start gap-4">
          <div class="w-14 h-14 bg-sky-100 rounded-2xl flex items-center justify-center flex-shrink-0">
            <i class="fas fa-snowflake text-sky-600 text-2xl"></i>
          </div>
          <div class="flex-1">
            <h3 class="text-lg font-bold text-gray-800 mb-1">北海道 情報政策課 調達情報</h3>
            <p class="text-sm text-gray-600 mb-3">北海道総務部イノベーション推進局情報政策課が発注する入札案件を取得します。</p>
            <a href="https://www.pref.hokkaido.lg.jp/sm/jsk/a0001/b0002/" target="_blank"
               class="text-xs bg-white border border-sky-200 text-sky-600 px-3 py-1.5 rounded-lg hover:bg-sky-50 inline-flex items-center gap-1">
              <i class="fas fa-external-link-alt"></i> 公式サイトを開く
            </a>
          </div>
        </div>
      </div>
      <div class="bg-white rounded-2xl shadow-sm border border-gray-100 p-5 mb-6">
        <div class="flex flex-wrap items-end gap-4">
          <div class="flex-1 min-w-48">
            <label class="block text-xs font-medium text-gray-600 mb-1">キーワード</label>
            <input id="hokkaido-query" type="text" placeholder="案件名で絞り込み..."
              class="w-full px-3 py-2.5 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-sky-300"
              onkeypress="if(event.key==='Enter') loadHokkaido()">
          </div>
          <button onclick="loadHokkaido()"
            class="px-6 py-2.5 rounded-xl font-medium text-sm text-white shadow-md flex items-center gap-2"
            style="background: linear-gradient(135deg, #0284c7, #0369a1);">
            <i class="fas fa-search"></i> 取得する
          </button>
        </div>
      </div>
      <div id="hokkaido-result-area"></div>
    </div>

    <!-- 今治市産業振興課ページ -->
    <div id="page-imabari" class="page-content hidden">
      <div class="bg-gradient-to-br from-lime-50 to-green-50 border border-lime-100 rounded-2xl p-6 mb-6">
        <div class="flex items-start gap-4">
          <div class="w-14 h-14 bg-lime-100 rounded-2xl flex items-center justify-center flex-shrink-0">
            <i class="fas fa-map-marker-alt text-lime-600 text-2xl"></i>
          </div>
          <div class="flex-1">
            <h3 class="text-lg font-bold text-gray-800 mb-1">今治市 産業振興課 調達情報</h3>
            <p class="text-sm text-gray-600 mb-3">今治市産業振興課のプロポーザル案件を取得します。</p>
            <a href="https://www.city.imabari.ehime.jp/sangyou/new.html" target="_blank"
               class="text-xs bg-white border border-lime-200 text-lime-600 px-3 py-1.5 rounded-lg hover:bg-lime-50 inline-flex items-center gap-1">
              <i class="fas fa-external-link-alt"></i> 公式サイトを開く
            </a>
          </div>
        </div>
      </div>
      <div class="bg-white rounded-2xl shadow-sm border border-gray-100 p-5 mb-6">
        <div class="flex flex-wrap items-end gap-4">
          <div class="flex-1 min-w-48">
            <label class="block text-xs font-medium text-gray-600 mb-1">キーワード</label>
            <input id="imabari-query" type="text" placeholder="案件名で絞り込み..."
              class="w-full px-3 py-2.5 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-lime-300"
              onkeypress="if(event.key==='Enter') loadImabari()">
          </div>
          <button onclick="loadImabari()"
            class="px-6 py-2.5 rounded-xl font-medium text-sm text-white shadow-md flex items-center gap-2"
            style="background: linear-gradient(135deg, #65a30d, #4d7c0f);">
            <i class="fas fa-search"></i> 取得する
          </button>
        </div>
      </div>
      <div id="imabari-result-area"></div>
    </div>

    <!-- 長野県営業局ページ -->
    <div id="page-nagano" class="page-content hidden">
      <div class="bg-gradient-to-br from-purple-50 to-violet-50 border border-purple-100 rounded-2xl p-6 mb-6">
        <div class="flex items-start gap-4">
          <div class="w-14 h-14 bg-purple-100 rounded-2xl flex items-center justify-center flex-shrink-0">
            <i class="fas fa-mountain text-purple-600 text-2xl"></i>
          </div>
          <div class="flex-1">
            <h3 class="text-lg font-bold text-gray-800 mb-1">長野県 営業局 調達情報</h3>
            <p class="text-sm text-gray-600 mb-3">長野県営業局のプロポーザル公募案件を取得します。</p>
            <a href="https://www.pref.nagano.lg.jp/eigyo/0415propo.html" target="_blank"
               class="text-xs bg-white border border-purple-200 text-purple-600 px-3 py-1.5 rounded-lg hover:bg-purple-50 inline-flex items-center gap-1">
              <i class="fas fa-external-link-alt"></i> 公式サイトを開く
            </a>
          </div>
        </div>
      </div>
      <div class="bg-white rounded-2xl shadow-sm border border-gray-100 p-5 mb-6">
        <div class="flex flex-wrap items-end gap-4">
          <div class="flex-1 min-w-48">
            <label class="block text-xs font-medium text-gray-600 mb-1">キーワード</label>
            <input id="nagano-query" type="text" placeholder="案件名で絞り込み..."
              class="w-full px-3 py-2.5 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-purple-300"
              onkeypress="if(event.key==='Enter') loadNagano()">
          </div>
          <button onclick="loadNagano()"
            class="px-6 py-2.5 rounded-xl font-medium text-sm text-white shadow-md flex items-center gap-2"
            style="background: linear-gradient(135deg, #7c3aed, #6d28d9);">
            <i class="fas fa-search"></i> 取得する
          </button>
        </div>
      </div>
      <div id="nagano-result-area"></div>
    </div>

    <!-- 全ソース一括検索ページ -->
    <div id="page-all" class="page-content hidden">
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          <div class="md:col-span-2">
            <label class="block text-xs font-medium text-gray-600 mb-1">キーワード</label>
            <input id="all-query" type="text" placeholder="案件名・内容で横断検索..."
              class="w-full px-3 py-2.5 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-300"
              onkeypress="if(event.key==='Enter') loadAll()">
          </div>
          <div>
            <label class="block text-xs font-medium text-gray-600 mb-1">検索対象ソース</label>
            <div class="grid grid-cols-2 gap-1.5 pt-1">
              <label class="flex items-center gap-2 text-sm text-gray-700 cursor-pointer">
                <input type="checkbox" id="src-kkj" checked class="rounded text-indigo-600"> 官公需ポータル
              </label>
              <label class="flex items-center gap-2 text-sm text-gray-700 cursor-pointer">
                <input type="checkbox" id="src-kkp" checked class="rounded text-rose-600"> 協会けんぽ
              </label>
              <label class="flex items-center gap-2 text-sm text-gray-700 cursor-pointer">
                <input type="checkbox" id="src-pfa" checked class="rounded text-amber-600"> 企業年金連合会
              </label>
              <label class="flex items-center gap-2 text-sm text-gray-700 cursor-pointer">
                <input type="checkbox" id="src-jeed" checked class="rounded text-green-600"> JEED雇用支援機構
              </label>
              <label class="flex items-center gap-2 text-sm text-gray-700 cursor-pointer">
                <input type="checkbox" id="src-jfc" checked class="rounded text-blue-600"> 日本政策金融公庫
              </label>
              <label class="flex items-center gap-2 text-sm text-gray-700 cursor-pointer">
                <input type="checkbox" id="src-fsa" checked class="rounded text-orange-600"> 金融庁
              </label>
              <label class="flex items-center gap-2 text-sm text-gray-700 cursor-pointer">
                <input type="checkbox" id="src-uitec" checked class="rounded text-emerald-600"> 職業能力開発大学校
              </label>
              <label class="flex items-center gap-2 text-sm text-gray-700 cursor-pointer">
                <input type="checkbox" id="src-osaka" checked class="rounded text-pink-600"> 大阪市DX統括室
              </label>
              <label class="flex items-center gap-2 text-sm text-gray-700 cursor-pointer">
                <input type="checkbox" id="src-hokkaido" checked class="rounded text-sky-600"> 北海道情報政策課
              </label>
              <label class="flex items-center gap-2 text-sm text-gray-700 cursor-pointer">
                <input type="checkbox" id="src-imabari" checked class="rounded text-lime-600"> 今治市産業振興課
              </label>
              <label class="flex items-center gap-2 text-sm text-gray-700 cursor-pointer">
                <input type="checkbox" id="src-nagano" checked class="rounded text-purple-600"> 長野県営業局
              </label>
              <label class="flex items-center gap-2 text-sm text-gray-700 cursor-pointer">
                <input type="checkbox" id="src-ipa" checked class="rounded text-sky-600"> IPA情報処理推進機構
              </label>
              <label class="flex items-center gap-2 text-sm text-gray-700 cursor-pointer">
                <input type="checkbox" id="src-bosai" checked class="rounded text-orange-600"> 防災科学技術研究所
              </label>
            </div>
          </div>
        </div>
        <!-- 検索対象・AND検索オプション -->
        <div class="bg-gray-50 rounded-xl px-4 py-3 mb-4 flex flex-wrap items-center gap-4">
          <div class="flex items-center gap-1 text-xs font-medium text-gray-600">
            <i class="fas fa-sliders-h text-indigo-500 mr-1"></i>検索対象：
          </div>
          <label class="flex items-center gap-1.5 text-xs text-gray-700 cursor-pointer">
            <input type="checkbox" id="all-sf-name" checked class="accent-indigo-500"> 案件名
          </label>
          <label class="flex items-center gap-1.5 text-xs text-gray-700 cursor-pointer">
            <input type="checkbox" id="all-sf-desc" class="accent-indigo-500"> 説明文
            <span class="text-gray-400">（官公需ポータルのみ）</span>
          </label>
          <label class="flex items-center gap-1.5 text-xs text-gray-700 cursor-pointer">
            <input type="checkbox" id="all-sf-org" class="accent-indigo-500"> 機関名
          </label>
          <div class="border-l border-gray-300 pl-4 flex items-center gap-1.5 text-xs text-gray-500">
            <i class="fas fa-info-circle text-indigo-400"></i>
            スペース区切りで<strong class="text-gray-700">AND検索</strong>
          </div>
        </div>
        <button onclick="loadAll()"
          class="btn-primary text-white px-8 py-2.5 rounded-xl font-medium text-sm shadow-md flex items-center gap-2">
          <i class="fas fa-search"></i> 一括検索する
        </button>
      </div>
      <div id="all-result-area"></div>
    </div>

    <!-- メール通知設定ページ -->
    <!-- ブックマークページ -->
    <div id="page-bookmark" class="page-content hidden">
      <!-- ヘッダーカード -->
      <div class="bg-gradient-to-br from-yellow-50 to-amber-50 border border-yellow-100 rounded-2xl p-6 mb-6">
        <div class="flex items-start gap-4">
          <div class="w-14 h-14 bg-yellow-100 rounded-2xl flex items-center justify-center flex-shrink-0">
            <i class="fas fa-star text-yellow-500 text-2xl"></i>
          </div>
          <div class="flex-1">
            <h3 class="text-lg font-bold text-gray-800 mb-1">ブックマーク</h3>
            <p class="text-sm text-gray-600">気になる案件を保存しておけます。このPCのブラウザに保存されます。</p>
          </div>
          <button onclick="clearAllBookmarks()" class="text-xs text-red-400 hover:text-red-600 border border-red-200 hover:border-red-400 px-3 py-1.5 rounded-lg transition-all">
            <i class="fas fa-trash mr-1"></i>すべて削除
          </button>
        </div>
      </div>
      <!-- ブックマーク一覧 -->
      <div id="bookmark-list-area"></div>
    </div>

    <div id="page-notify" class="page-content hidden">

      <!-- ヘッダーカード -->
      <div class="bg-gradient-to-br from-violet-50 to-purple-50 border border-violet-100 rounded-2xl p-6 mb-6">
        <div class="flex items-start gap-4">
          <div class="w-14 h-14 bg-violet-100 rounded-2xl flex items-center justify-center flex-shrink-0">
            <i class="fas fa-bell text-violet-600 text-2xl"></i>
          </div>
          <div class="flex-1">
            <h3 class="text-lg font-bold text-gray-800 mb-1">メール通知設定</h3>
            <p class="text-sm text-gray-600">設定したキーワードに一致する新着案件が見つかった際に、メールで自動通知します。<br>毎日 <strong>午前11時</strong> に全ソースをチェックします。</p>
          </div>
        </div>
      </div>

      <!-- 現在の設定表示 -->
      <div class="bg-white rounded-2xl shadow-sm border border-gray-100 p-6 mb-6">
        <h4 class="font-bold text-gray-700 mb-4 flex items-center gap-2">
          <i class="fas fa-cog text-gray-400"></i> 現在の通知設定
        </h4>
        <div id="notify-status-area">
          <div class="flex justify-center py-8">
            <div class="loading-spinner"></div>
          </div>
        </div>
      </div>

      <!-- 手動テスト -->
      <div class="bg-white rounded-2xl shadow-sm border border-gray-100 p-6 mb-6">
        <h4 class="font-bold text-gray-700 mb-2 flex items-center gap-2">
          <i class="fas fa-vial text-violet-500"></i> 今すぐ通知チェックを実行
        </h4>
        <p class="text-sm text-gray-500 mb-4">手動でキーワードチェックを実行し、新着案件があればメールを送信します。</p>
        <div class="flex items-center gap-3">
          <button onclick="runNotifyCheck()"
            class="px-6 py-2.5 rounded-xl font-medium text-sm text-white shadow-md flex items-center gap-2"
            style="background: linear-gradient(135deg, #7c3aed, #6d28d9);">
            <i class="fas fa-play"></i> チェックを実行する
          </button>
          <span id="notify-run-status" class="text-sm text-gray-500"></span>
        </div>
        <div id="notify-run-result" class="mt-4 hidden"></div>
      </div>

      <!-- スケジュール情報 -->
      <div class="bg-white rounded-2xl shadow-sm border border-gray-100 p-6">
        <h4 class="font-bold text-gray-700 mb-4 flex items-center gap-2">
          <i class="fas fa-clock text-gray-400"></i> 自動実行スケジュール
        </h4>
        <div class="bg-gray-50 rounded-xl p-4 text-sm text-gray-600 space-y-2">
          <div class="flex items-center gap-3">
            <i class="fas fa-check-circle text-green-500 w-4"></i>
            <span>毎日 <strong>11:00 (JST)</strong> に自動チェック</span>
          </div>
          <div class="flex items-center gap-3">
            <i class="fas fa-check-circle text-green-500 w-4"></i>
            <span>対象ソース: 官公需ポータル・協会けんぽ・企業年金連合会</span>
          </div>
          <div class="flex items-center gap-3">
            <i class="fas fa-check-circle text-green-500 w-4"></i>
            <span>監視キーワード: <strong>動画制作</strong>・<strong>研修</strong></span>
          </div>
          <div class="flex items-center gap-3">
            <i class="fas fa-check-circle text-green-500 w-4"></i>
            <span>通知先: contents@onsuku.jp・ons.test.888@gmail.com</span>
          </div>
          <div class="flex items-center gap-3">
            <i class="fas fa-info-circle text-blue-400 w-4"></i>
            <span class="text-gray-500">前回チェック以降の新着案件のみ通知（重複通知なし）</span>
          </div>
        </div>
      </div>

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
// 認証管理
// ========================
const TOKEN_KEY = 'biddx_token';

function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

function setToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}

function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

function isLoggedIn() {
  const token = getToken();
  if (!token) return false;
  // JWTのペイロードをデコードして期限確認
  try {
    const payload = JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
    return payload.exp > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

function authHeaders() {
  const token = getToken();
  return token ? { Authorization: 'Bearer ' + token } : {};
}

async function doLogin() {
  const password = document.getElementById('login-password').value.trim();
  if (!password) return;

  const btn = document.getElementById('login-btn');
  const errDiv = document.getElementById('login-error');
  const errMsg = document.getElementById('login-error-msg');
  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>ログイン中...';
  errDiv.classList.add('hidden');

  try {
    const res = await axios.post('/api/login', { password });
    setToken(res.data.token);
    showApp();
  } catch (e) {
    const msg = e.response?.data?.error || 'ログインに失敗しました';
    errMsg.textContent = msg;
    errDiv.classList.remove('hidden');
    document.getElementById('login-password').value = '';
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-sign-in-alt mr-2"></i>ログイン';
  }
}

function doLogout() {
  clearToken();
  showLogin();
}

function showLogin() {
  document.getElementById('login-overlay').classList.remove('hidden');
  document.getElementById('sidebar').classList.add('hidden');
  document.querySelector('.ml-64').classList.add('hidden');
  document.getElementById('login-password').value = '';
  document.getElementById('login-error').classList.add('hidden');
}

function showApp() {
  document.getElementById('login-overlay').classList.add('hidden');
  document.getElementById('sidebar').classList.remove('hidden');
  document.querySelector('.ml-64').classList.remove('hidden');
}

// axios のデフォルトヘッダーに認証トークンを付与
axios.interceptors.request.use(config => {
  const token = getToken();
  if (token) config.headers['Authorization'] = 'Bearer ' + token;
  return config;
});

// 401レスポンスの場合はログイン画面へ
axios.interceptors.response.use(
  res => res,
  err => {
    if (err.response?.status === 401) {
      clearToken();
      showLogin();
    }
    return Promise.reject(err);
  }
);

// ========================
// グローバル状態
// ========================
let currentPage = 'dashboard';
let searchResults = [];
let showClosedItems = false; // 締切済み案件を表示するか

// ========================
// ページ遷移
// ========================
function showPage(page) {
  document.querySelectorAll('.page-content').forEach(el => el.classList.add('hidden'));
  document.querySelectorAll('.sidebar-link').forEach(el => el.classList.remove('active'));

  document.getElementById('page-' + page).classList.remove('hidden');
  const navEl = document.getElementById('nav-' + page);
  if (navEl) navEl.classList.add('active');
  currentPage = page;

  const titles = {
    dashboard: 'ダッシュボード',
    search: '案件検索',
    new: '新着案件',
    construction: '工事案件',
    goods: '物品案件',
    service: '役務案件',
    kyoukaikenpo: '協会けんぽ 調達情報',
    pfa: '企業年金連合会 調達情報',
    jeed: 'JEED 高齢・障害・求職者雇用支援機構 調達情報',
    uitec: '職業能力開発総合大学校（UITEC）調達情報',
    jfc: '日本政策金融公庫 調達情報',
    fsa: '金融庁 調達情報',
    osaka: '大阪市デジタル統括室 調達情報',
    hokkaido: '北海道 情報政策課 調達情報',
    imabari: '今治市 産業振興課 調達情報',
    nagano: '長野県 営業局 調達情報',
    ipa: 'IPA 情報処理推進機構 調達情報',
    bosai: '防災科学技術研究所 調達情報',
    all: '全ソース一括検索',
    bookmark: 'ブックマーク',
    notify: 'メール通知設定',
    mod: '防衛省（内局）調達情報',
    'mod-dih': '防衛省情報本部 調達情報',
  };
  const subtitles = {
    dashboard: '官公需ポータル・協会けんぽ・企業年金連合会のリアルタイムデータ',
    search: '官公需情報ポータルサイト (kkj.go.jp) のリアルタイムデータ',
    new: '官公需情報ポータルサイト (kkj.go.jp) のリアルタイムデータ',
    construction: '官公需情報ポータルサイト (kkj.go.jp) のリアルタイムデータ',
    goods: '官公需情報ポータルサイト (kkj.go.jp) のリアルタイムデータ',
    service: '官公需情報ポータルサイト (kkj.go.jp) のリアルタイムデータ',
    kyoukaikenpo: '全国健康保険協会 公式サイトから直接取得',
    pfa: '企業年金連合会 公式サイトから直接取得',
    jeed: '独立行政法人高齢・障害・求職者雇用支援機構 公式サイトから直接取得',
    uitec: '職業能力開発総合大学校 公式サイトから直接取得',
    jfc: '株式会社日本政策金融公庫 公式サイトから直接取得',
    fsa: '金融庁 公式サイトから直接取得',
    osaka: '大阪市デジタル統括室 公式サイトから直接取得',
    hokkaido: '北海道総合振興局 情報政策課 公式サイトから直接取得',
    imabari: '今治市産業振興課 公式サイトから直接取得',
    nagano: '長野県営業局 公式サイトから直接取得',
    ipa: '独立行政法人情報処理推進機構 公式サイトから直接取得',
    bosai: '国立研究開発法人防災科学技術研究所 公式サイトから直接取得',
    all: '官公需ポータル・協会けんぽ・企業年金連合会・JEED・JFC・IPA・防災科研・大阪市・北海道・今治市・長野県 横断検索',
    bookmark: 'ブラウザのlocalStorageに保存（このPCのみ）',
    notify: 'キーワード一致の新着案件をメールで自動通知',
    mod: '防衛省大臣官房会計課 公式サイトから直接取得',
    'mod-dih': '防衛省情報本部 公式サイトから直接取得',
  };
  document.getElementById('page-title').textContent = titles[page] || page;
  const subtitleEl = document.getElementById('page-subtitle');
  if (subtitleEl) subtitleEl.textContent = subtitles[page] || '';

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
  } else if (page === 'kyoukaikenpo') {
    loadKyoukaikenpo();
  } else if (page === 'pfa') {
    loadPfa();
  } else if (page === 'jeed') {
    loadJeed();
  } else if (page === 'uitec') {
    loadUitec();
  } else if (page === 'jfc') {
    loadJfc();
  } else if (page === 'fsa') {
    loadFsa();
  } else if (page === 'osaka') {
    loadOsaka();
  } else if (page === 'hokkaido') {
    loadHokkaido();
  } else if (page === 'imabari') {
    loadImabari();
  } else if (page === 'nagano') {
    loadNagano();
  } else if (page === 'ipa') {
    loadIpa();
  } else if (page === 'bosai') {
    loadBosai();
  } else if (page === 'mod') {
    loadMod();
  } else if (page === 'mod-dih') {
    loadModDih();
  } else if (page === 'all') {
    loadAll();
  } else if (page === 'bookmark') {
    renderBookmarkPage();
  } else if (page === 'notify') {
    loadNotifyStatus();
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

  // 検索対象フィールドを取得
  const sfName = document.getElementById('sf-name')?.checked;
  const sfDesc = document.getElementById('sf-desc')?.checked;
  const sfOrg  = document.getElementById('sf-org')?.checked;
  const searchFields = [sfName && 'name', sfDesc && 'desc', sfOrg && 'org'].filter(Boolean).join(',') || 'name';

  const area = document.getElementById('search-result-area');
  area.innerHTML = \`<div class="flex justify-center py-16"><div class="text-center"><div class="loading-spinner mx-auto mb-4"></div><p class="text-gray-500 text-sm">検索中...</p></div></div>\`;

  try {
    const params = { count, searchFields };
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

  // 締切済みフィルタリング
  const activeItems = showClosedItems ? items : items.filter(item => !isItemClosed(item));
  const closedCount = items.length - activeItems.length;

  let html = \`
    <div class="bg-white rounded-2xl shadow-sm border border-gray-100 mb-6">
      <div class="p-4 border-b border-gray-100 flex items-center justify-between flex-wrap gap-2">
        <h3 class="font-bold text-gray-800 text-sm flex items-center gap-2">
          <i class="fas fa-list text-blue-500"></i>
          \${label}
          <span class="ml-2 text-xs bg-blue-50 text-blue-600 px-2 py-0.5 rounded-full font-normal">
            \${activeItems.length} 件表示
            \${closedCount > 0 ? \`<span class="text-gray-400 ml-1">（締切済み \${closedCount} 件非表示）</span>\` : ''}
          </span>
        </h3>
        <div class="flex gap-2 flex-wrap">
          \${closedCount > 0 ? \`
          <button onclick="toggleClosedItems('" + areaId + "')" class="text-xs px-3 py-1.5 border rounded-lg \${showClosedItems ? 'bg-gray-200 text-gray-700 border-gray-300' : 'text-gray-500 hover:text-blue-600 border-gray-200 hover:border-blue-300'}">
            <i class="fas fa-eye\${showClosedItems ? '-slash' : ''} mr-1"></i>\${showClosedItems ? '締切済みを隠す' : '締切済みも表示'}
          </button>\` : ''}
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

  activeItems.forEach(item => {
    html += renderListItem(item);
  });

  if (activeItems.length === 0 && closedCount > 0) {
    html += \`<div class="text-center py-12">
      <i class="fas fa-check-circle text-gray-300 text-4xl mb-4"></i>
      <p class="text-gray-500">募集中の案件はありません</p>
      <p class="text-xs text-gray-400 mt-2">締切済み \${closedCount} 件が非表示です</p>
      <button onclick="toggleClosedItems('\${areaId}')" class="mt-3 text-xs text-blue-600 hover:underline">締切済みも表示する</button>
    </div>\`;
  }

  html += \`</div></div>\`;
  area.innerHTML = html;
  searchResults = items;
}

function toggleClosedItems(areaId) {
  showClosedItems = !showClosedItems;
  // 現在の表示中のページを再レンダリング
  const area = document.getElementById(areaId);
  if (!area || !searchResults.length) return;
  // renderResults を再呼び出し
  renderResults(areaId, { items: searchResults, totalHits: searchResults.length }, '検索結果');
}

// ========================
// ブックマーク機能
// ========================
const BOOKMARK_KEY = 'biddx_bookmarks';

function getBookmarks() {
  try {
    return JSON.parse(localStorage.getItem(BOOKMARK_KEY) || '[]');
  } catch { return []; }
}

function saveBookmarks(bookmarks) {
  localStorage.setItem(BOOKMARK_KEY, JSON.stringify(bookmarks));
  updateBookmarkBadge();
}

function getBookmarkId(item) {
  return item.resultId || item.url || item.projectName || '';
}

function isBookmarked(item) {
  const id = getBookmarkId(item);
  if (!id) return false;
  return getBookmarks().some(b => getBookmarkId(b) === id);
}

function toggleBookmark(item) {
  const id = getBookmarkId(item);
  if (!id) return;
  let bookmarks = getBookmarks();
  const idx = bookmarks.findIndex(b => getBookmarkId(b) === id);
  if (idx >= 0) {
    bookmarks.splice(idx, 1);
  } else {
    bookmarks.unshift({ ...item, bookmarkedAt: new Date().toISOString() });
  }
  saveBookmarks(bookmarks);
  // ブックマークボタンのアイコンを更新
  document.querySelectorAll(\`.bookmark-btn[data-id="\${CSS.escape(id)}"]\`).forEach(btn => {
    const bookmarked = bookmarks.some(b => getBookmarkId(b) === id);
    btn.innerHTML = bookmarked
      ? '<i class="fas fa-star text-yellow-400"></i>'
      : '<i class="far fa-star text-gray-300 hover:text-yellow-400"></i>';
    btn.title = bookmarked ? 'ブックマーク解除' : 'ブックマークに追加';
  });
}

function clearAllBookmarks() {
  if (!confirm('すべてのブックマークを削除しますか？')) return;
  saveBookmarks([]);
  renderBookmarkPage();
}

function updateBookmarkBadge() {
  const count = getBookmarks().length;
  const badge = document.getElementById('bookmark-count-badge');
  if (!badge) return;
  if (count > 0) {
    badge.textContent = count;
    badge.classList.remove('hidden');
  } else {
    badge.classList.add('hidden');
  }
}

function renderBookmarkPage() {
  const area = document.getElementById('bookmark-list-area');
  if (!area) return;
  const bookmarks = getBookmarks();

  if (bookmarks.length === 0) {
    area.innerHTML = \`
      <div class="text-center py-20 bg-white rounded-2xl border border-gray-100">
        <i class="far fa-star text-gray-200 text-5xl mb-4"></i>
        <p class="text-gray-500 text-lg font-medium">ブックマークはありません</p>
        <p class="text-xs text-gray-400 mt-2">案件一覧の ☆ アイコンをクリックして追加できます</p>
      </div>\`;
    return;
  }

  // 締切済みフィルタ
  const activeItems = showClosedItems ? bookmarks : bookmarks.filter(item => !isItemClosed(item));
  const closedCount = bookmarks.length - activeItems.length;

  let html = \`
    <div class="bg-white rounded-2xl shadow-sm border border-gray-100 mb-6">
      <div class="p-4 border-b border-gray-100 flex items-center justify-between flex-wrap gap-2">
        <h3 class="font-bold text-gray-800 text-sm flex items-center gap-2">
          <i class="fas fa-star text-yellow-400"></i>
          保存済み案件
          <span class="ml-2 text-xs bg-yellow-50 text-yellow-600 px-2 py-0.5 rounded-full font-normal">
            \${activeItems.length} 件
            \${closedCount > 0 ? \`<span class="text-gray-400 ml-1">（締切済み \${closedCount} 件非表示）</span>\` : ''}
          </span>
        </h3>
        \${closedCount > 0 ? \`
        <button onclick="showClosedItems=!showClosedItems; renderBookmarkPage();" class="text-xs px-3 py-1.5 border rounded-lg \${showClosedItems ? 'bg-gray-200 text-gray-700 border-gray-300' : 'text-gray-500 hover:text-blue-600 border-gray-200 hover:border-blue-300'}">
          <i class="fas fa-eye\${showClosedItems ? '-slash' : ''} mr-1"></i>\${showClosedItems ? '締切済みを隠す' : '締切済みも表示'}
        </button>\` : ''}
      </div>
      <div class="divide-y divide-gray-50">\`;

  if (activeItems.length === 0 && closedCount > 0) {
    html += \`<div class="text-center py-12">
      <i class="fas fa-check-circle text-gray-300 text-4xl mb-4"></i>
      <p class="text-gray-500">募集中のブックマークはありません</p>
      <button onclick="showClosedItems=true; renderBookmarkPage();" class="mt-3 text-xs text-blue-600 hover:underline">締切済みも表示する</button>
    </div>\`;
  } else {
    activeItems.forEach(item => {
      html += renderListItem(item);
    });
  }

  html += \`</div></div>\`;
  area.innerHTML = html;
}

function renderListItem(item) {
  const catBadge = getCategoryBadge(item.category);
  const procBadge = item.procedureType ? \`<span class="tag bg-gray-100 text-gray-600">\${item.procedureType}</span>\` : '';
  const issueDate = formatDisplayDate(item.cftIssueDate);
  const deadlineField = getDeadlineField(item);
  const deadline = formatDisplayDate(deadlineField);
  const openDate = formatDisplayDate(item.openingTendersEvent);
  const { status } = getDeadlineStatus(item);
  const deadlineBadge = renderDeadlineBadge(item);
  const isClosed = status === 'closed';
  const bookmarked = isBookmarked(item);
  const itemId = getBookmarkId(item);
  const itemJson = JSON.stringify(item).replace(/'/g, "\\\\'");

  return \`
    <div class="result-row px-6 py-4\${isClosed ? ' opacity-50' : ''}">
      <div class="flex items-start justify-between gap-4">
        <div class="flex-1 min-w-0 cursor-pointer" onclick='showModal(\${itemJson})'>
          <div class="flex flex-wrap items-center gap-2 mb-2">
            \${catBadge}
            \${procBadge}
            \${deadlineBadge}
          </div>
          <h4 class="text-sm font-semibold \${isClosed ? 'text-gray-400 line-through' : 'text-gray-800'} leading-snug mb-2 line-clamp-2 hover:text-blue-600">
            \${escHtml(item.projectName || '（案件名なし）')}
          </h4>
          <div class="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-gray-500">
            \${item.organizationName ? \`<span><i class="fas fa-building mr-1 text-gray-400"></i>\${escHtml(item.organizationName)}</span>\` : ''}
            \${item.prefectureName ? \`<span><i class="fas fa-map-marker-alt mr-1 text-gray-400"></i>\${escHtml(item.prefectureName)}\${item.cityName ? ' ' + escHtml(item.cityName) : ''}</span>\` : ''}
            \${issueDate ? \`<span><i class="fas fa-calendar mr-1 text-gray-400"></i>公告: \${issueDate}</span>\` : ''}
            \${deadline ? \`<span class="\${status === 'urgent' ? 'text-red-500 font-medium' : status === 'warn' ? 'text-yellow-600 font-medium' : ''}"><i class="fas fa-clock mr-1 text-gray-400"></i>締切: \${deadline}</span>\` : ''}
            \${openDate ? \`<span><i class="fas fa-gavel mr-1 text-gray-400"></i>開札: \${openDate}</span>\` : ''}
          </div>
        </div>
        <div class="flex-shrink-0 flex items-center gap-2">
          <button
            class="bookmark-btn p-2 rounded-lg hover:bg-yellow-50 transition-all"
            data-id="\${escHtml(itemId)}"
            title="\${bookmarked ? 'ブックマーク解除' : 'ブックマークに追加'}"
            onclick="event.stopPropagation(); toggleBookmark(\${itemJson}); if(currentPage==='bookmark') renderBookmarkPage();"
          >
            \${bookmarked
              ? '<i class="fas fa-star text-yellow-400"></i>'
              : '<i class="far fa-star text-gray-300 hover:text-yellow-400"></i>'}
          </button>
          <i class="fas fa-chevron-right text-gray-300 text-sm cursor-pointer" onclick='showModal(\${itemJson})'></i>
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
// 協会けんぽ
// ========================
async function loadKyoukaikenpo() {
  const area = document.getElementById('kkp-result-area');
  const query = document.getElementById('kkp-query').value.trim();
  const archive = document.getElementById('kkp-archive').value;

  area.innerHTML = \`<div class="flex justify-center py-16"><div class="text-center"><div class="loading-spinner mx-auto mb-4"></div><p class="text-gray-500 text-sm">協会けんぽから調達情報を取得中...</p></div></div>\`;

  try {
    const params = {};
    if (query) params.query = query;
    if (archive) params.archive = archive;

    const res = await axios.get('/api/kyoukaikenpo', { params });
    const data = res.data;

    if (!data.items || data.items.length === 0) {
      area.innerHTML = \`<div class="text-center py-16 bg-white rounded-2xl border border-gray-100">
        <i class="fas fa-search text-gray-300 text-4xl mb-4"></i>
        <p class="text-gray-500 text-lg">案件が見つかりませんでした</p>
      </div>\`;
      return;
    }

    // 入札種別でグループ化
    const groups = {};
    data.items.forEach(item => {
      const key = item.procedureType || 'その他';
      if (!groups[key]) groups[key] = [];
      groups[key].push(item);
    });

    const archiveLabels = { 'r07': '令和7年度', 'r06': '令和6年度', 'r05': '令和5年度' };
    const archiveLabel = archive ? (archiveLabels[archive] || archive) : '令和8年度（公開中）';

    const badgeColors = {
      '一般競争入札': 'bg-blue-50 text-blue-700 border border-blue-200',
      '見積競争': 'bg-green-50 text-green-700 border border-green-200',
      '企画競争': 'bg-purple-50 text-purple-700 border border-purple-200',
      '公募': 'bg-orange-50 text-orange-700 border border-orange-200',
    };

    let html = \`<div class="space-y-6">\`;

    for (const [groupName, groupItems] of Object.entries(groups)) {
      const badgeCls = badgeColors[groupName] || 'bg-gray-50 text-gray-700 border border-gray-200';
      html += \`
        <div class="bg-white rounded-2xl shadow-sm border border-gray-100">
          <div class="p-5 border-b border-gray-100 flex items-center justify-between">
            <h3 class="font-bold text-gray-800 flex items-center gap-2">
              <span class="tag \${badgeCls} text-sm px-3 py-1">\${escHtml(groupName)}</span>
              <span class="text-xs text-gray-500">\${groupItems.length}件</span>
            </h3>
          </div>
          <div class="divide-y divide-gray-50">
      \`;
      groupItems.forEach(item => {
        const issueDate = formatDisplayDate(item.cftIssueDate);
        const pdfUrl = item.url || '';
        html += \`
          <div class="px-5 py-4 hover:bg-rose-50 transition-colors cursor-pointer" onclick='showModal(\${JSON.stringify(item).replace(/'/g, "\\\\'")})'>\`
          + \`
            <div class="flex items-start justify-between gap-4">
              <div class="flex-1 min-w-0">
                <div class="flex items-center gap-2 mb-1">
                  \${issueDate ? \`<span class="text-xs text-gray-400"><i class="fas fa-calendar mr-1"></i>\${issueDate}</span>\` : ''}
                </div>
                <p class="text-sm font-medium text-gray-800 leading-snug hover:text-rose-700">\${escHtml(item.projectName)}</p>
              </div>
              <div class="flex items-center gap-2 flex-shrink-0">
                \${pdfUrl.endsWith('.pdf') ? \`
                  <a href="\${escHtml(pdfUrl)}" target="_blank" onclick="event.stopPropagation()"
                     class="text-xs bg-red-50 text-red-600 border border-red-200 px-2.5 py-1 rounded-lg hover:bg-red-100 flex items-center gap-1">
                    <i class="fas fa-file-pdf"></i> PDF
                  </a>
                \` : ''}
                <i class="fas fa-chevron-right text-gray-300 text-xs"></i>
              </div>
            </div>
          </div>
        \`;
      });
      html += \`</div></div>\`;
    }

    html += \`</div>
      <div class="mt-4 text-center text-xs text-gray-400">
        <i class="fas fa-info-circle mr-1"></i>
        データ出典: <a href="https://www.kyoukaikenpo.or.jp/disclosure/procurement/" target="_blank" class="text-blue-400 hover:underline">全国健康保険協会 調達情報</a> (\${archiveLabel})
      </div>
    \`;

    area.innerHTML = html;
  } catch(e) {
    area.innerHTML = \`<div class="text-center py-16 bg-white rounded-2xl border border-gray-100">
      <i class="fas fa-exclamation-triangle text-yellow-500 text-3xl mb-3"></i>
      <p class="text-gray-600">取得に失敗しました</p>
      <p class="text-xs text-gray-400 mt-1">\${e.message}</p>
    </div>\`;
  }
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
// 企業年金連合会
// ========================
async function loadPfa() {
  const area = document.getElementById('pfa-result-area');
  const query = document.getElementById('pfa-query').value.trim();

  area.innerHTML = \`<div class="flex justify-center py-16"><div class="text-center"><div class="loading-spinner mx-auto mb-4"></div><p class="text-gray-500 text-sm">企業年金連合会から調達情報を取得中...</p></div></div>\`;

  try {
    const params = {};
    if (query) params.keyword = query;

    const res = await axios.get('/api/pfa', { params });
    const data = res.data;

    if (data.error) {
      area.innerHTML = \`<div class="text-center py-16 bg-white rounded-2xl border border-gray-100">
        <i class="fas fa-exclamation-triangle text-yellow-500 text-3xl mb-3"></i>
        <p class="text-gray-600">エラーが発生しました</p>
        <p class="text-xs text-gray-400 mt-1">\${escHtml(data.error)}</p>
        <p class="text-xs text-gray-400 mt-2">企業年金連合会のサイトが一時的に取得できない場合があります。<br>
          <a href="https://www.pfa.or.jp/chotatsu/ichiran/index.html" target="_blank" class="text-blue-500 hover:underline">公式サイトで直接ご確認ください</a>
        </p>
      </div>\`;
      return;
    }

    if (!data.items || data.items.length === 0) {
      area.innerHTML = \`<div class="text-center py-16 bg-white rounded-2xl border border-gray-100">
        <i class="fas fa-search text-gray-300 text-4xl mb-4"></i>
        <p class="text-gray-500 text-lg">案件が見つかりませんでした</p>
        <p class="text-xs text-gray-400 mt-2">
          <a href="https://www.pfa.or.jp/chotatsu/ichiran/index.html" target="_blank" class="text-blue-500 hover:underline">公式サイトで直接ご確認ください</a>
        </p>
      </div>\`;
      return;
    }

    let html = \`
      <div class="bg-white rounded-2xl shadow-sm border border-gray-100">
        <div class="p-5 border-b border-gray-100 flex items-center justify-between">
          <h3 class="font-bold text-gray-800 flex items-center gap-2">
            <i class="fas fa-list text-amber-500"></i>
            調達案件一覧
            <span class="ml-2 text-xs bg-amber-50 text-amber-600 px-2 py-0.5 rounded-full font-normal">
              \${data.totalHits} 件
            </span>
          </h3>
        </div>
        <div class="divide-y divide-gray-50">
    \`;

    data.items.forEach(item => {
      const issueDate = formatDisplayDate(item.cftIssueDate);
      html += \`
        <div class="px-5 py-4 hover:bg-amber-50 transition-colors cursor-pointer" onclick='showModal(\${JSON.stringify(item).replace(/'/g, "\\\\'")})'>\`
        + \`
          <div class="flex items-start justify-between gap-4">
            <div class="flex-1 min-w-0">
              <div class="flex items-center gap-2 mb-1">
                \${issueDate ? \`<span class="text-xs text-gray-400"><i class="fas fa-calendar mr-1"></i>\${issueDate}</span>\` : ''}
                <span class="tag bg-amber-50 text-amber-700 border border-amber-200 text-xs">入札・競争</span>
              </div>
              <p class="text-sm font-medium text-gray-800 leading-snug hover:text-amber-700">\${escHtml(item.projectName)}</p>
            </div>
            <div class="flex items-center gap-2 flex-shrink-0">
              \${(item.url && item.url.endsWith('.pdf')) ? \`
                <a href="\${escHtml(item.url)}" target="_blank" onclick="event.stopPropagation()"
                   class="text-xs bg-red-50 text-red-600 border border-red-200 px-2.5 py-1 rounded-lg hover:bg-red-100 flex items-center gap-1">
                  <i class="fas fa-file-pdf"></i> PDF
                </a>
              \` : ''}
              \${(item.attachments && item.attachments.some(a => a.uri.endsWith('.zip'))) ? \`
                <span class="text-xs bg-gray-50 text-gray-500 border border-gray-200 px-2.5 py-1 rounded-lg flex items-center gap-1">
                  <i class="fas fa-file-archive"></i> ZIP
                </span>
              \` : ''}
              <i class="fas fa-chevron-right text-gray-300 text-xs"></i>
            </div>
          </div>
        </div>
      \`;
    });

    html += \`</div></div>
      <div class="mt-4 text-center text-xs text-gray-400">
        <i class="fas fa-info-circle mr-1"></i>
        データ出典: <a href="https://www.pfa.or.jp/chotatsu/ichiran/index.html" target="_blank" class="text-blue-400 hover:underline">企業年金連合会 調達情報一覧</a>
      </div>
    \`;

    area.innerHTML = html;
  } catch(e) {
    area.innerHTML = \`<div class="text-center py-16 bg-white rounded-2xl border border-gray-100">
      <i class="fas fa-exclamation-triangle text-yellow-500 text-3xl mb-3"></i>
      <p class="text-gray-600">取得に失敗しました</p>
      <p class="text-xs text-gray-400 mt-1">\${e.message}</p>
    </div>\`;
  }
}

// ========================
// JEED（高齢・障害・求職者雇用支援機構）
// ========================
async function loadJeed() {
  const area = document.getElementById('jeed-result-area');
  const query = document.getElementById('jeed-query').value.trim();

  area.innerHTML = \`<div class="flex justify-center py-16"><div class="text-center"><div class="loading-spinner mx-auto mb-4"></div><p class="text-gray-500 text-sm">高齢・障害・求職者雇用支援機構から調達情報を取得中...</p></div></div>\`;

  try {
    const params = {};
    if (query) params.keyword = query;
    const res = await axios.get('/api/jeed', { params });
    const data = res.data;

    if (!data.items || data.items.length === 0) {
      area.innerHTML = \`<div class="text-center py-16 bg-white rounded-2xl border border-gray-100">
        <i class="fas fa-search text-gray-300 text-5xl mb-4"></i>
        <p class="text-gray-500 text-lg font-medium">案件が見つかりませんでした</p>
        <p class="text-gray-400 text-sm mt-2">キーワードを変更して再度お試しください</p>
      </div>\`;
      return;
    }

    let html = \`<div class="bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden">
      <div class="px-6 py-4 border-b border-gray-50 flex items-center justify-between">
        <span class="text-sm font-medium text-gray-700">
          <i class="fas fa-list text-teal-500 mr-2"></i>
          \${data.totalHits}件の案件
        </span>
      </div>
      <div class="divide-y divide-gray-50">
    \`;

    data.items.forEach(item => {
      const issueDate = formatDisplayDate(item.cftIssueDate);
      const deadlineStatus = item.tenderDeadline ? getDeadlineStatus(item.tenderDeadline) : null;
      html += \`
        <div class="px-5 py-4 hover:bg-teal-50 transition-colors cursor-pointer" onclick='showModal(\${JSON.stringify(item).replace(/'/g, "\\\\'")})'>\`
        + \`
          <div class="flex items-start justify-between gap-4">
            <div class="flex-1 min-w-0">
              <div class="flex items-center gap-2 mb-1">
                \${issueDate ? \`<span class="text-xs text-gray-400"><i class="fas fa-calendar mr-1"></i>\${issueDate}</span>\` : ''}
                <span class="tag bg-teal-50 text-teal-700 border border-teal-200 text-xs">入札公告</span>
                \${deadlineStatus ? \`<span class="\${deadlineStatus.cls} text-xs px-2 py-0.5 rounded-full">\${deadlineStatus.label}</span>\` : ''}
              </div>
              <p class="text-sm font-medium text-gray-800 leading-snug hover:text-teal-700">\${escHtml(item.projectName)}</p>
            </div>
            <div class="flex items-center gap-2 flex-shrink-0">
              \${(item.url && item.url.endsWith('.pdf')) ? \`
                <a href="\${escHtml(item.url)}" target="_blank" onclick="event.stopPropagation()"
                   class="text-xs bg-red-50 text-red-600 border border-red-200 px-2.5 py-1 rounded-lg hover:bg-red-100 flex items-center gap-1">
                  <i class="fas fa-file-pdf"></i> PDF
                </a>
              \` : ''}
              <i class="fas fa-chevron-right text-gray-300 text-xs"></i>
            </div>
          </div>
        </div>
      \`;
    });

    html += \`</div></div>
      <div class="mt-4 text-center text-xs text-gray-400">
        <i class="fas fa-info-circle mr-1"></i>
        データ出典: <a href="https://www.jeed.go.jp/jeed/information/honbu/chotatsu_buppin.html" target="_blank" class="text-blue-400 hover:underline">JEED 入札公告</a>
      </div>
    \`;

    area.innerHTML = html;
  } catch(e) {
    area.innerHTML = \`<div class="text-center py-16 bg-white rounded-2xl border border-gray-100">
      <i class="fas fa-exclamation-triangle text-yellow-500 text-3xl mb-3"></i>
      <p class="text-gray-600">取得に失敗しました</p>
      <p class="text-xs text-gray-400 mt-1">\${e.message}</p>
    </div>\`;
  }
}

// ========================
// JFC（日本政策金融公庫）
// ========================
async function loadJfc() {
  const area = document.getElementById('jfc-result-area');
  const query = document.getElementById('jfc-query').value.trim();

  area.innerHTML = \`<div class="flex justify-center py-16"><div class="text-center"><div class="loading-spinner mx-auto mb-4"></div><p class="text-gray-500 text-sm">日本政策金融公庫から調達情報を取得中...</p></div></div>\`;

  try {
    const params = {};
    if (query) params.keyword = query;
    const res = await axios.get('/api/jfc', { params });
    const data = res.data;

    if (!data.items || data.items.length === 0) {
      area.innerHTML = \`<div class="text-center py-16 bg-white rounded-2xl border border-gray-100">
        <i class="fas fa-search text-gray-300 text-5xl mb-4"></i>
        <p class="text-gray-500 text-lg font-medium">案件が見つかりませんでした</p>
        <p class="text-gray-400 text-sm mt-2">キーワードを変更して再度お試しください</p>
      </div>\`;
      return;
    }

    let html = \`<div class="bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden">
      <div class="px-6 py-4 border-b border-gray-50 flex items-center justify-between">
        <span class="text-sm font-medium text-gray-700">
          <i class="fas fa-list text-indigo-500 mr-2"></i>
          \${data.totalHits}件の案件
        </span>
      </div>
      <div class="divide-y divide-gray-50">
    \`;

    data.items.forEach(item => {
      const issueDate = formatDisplayDate(item.cftIssueDate);
      const deadlineStatus = item.tenderDeadline ? getDeadlineStatus(item.tenderDeadline) : null;
      html += \`
        <div class="px-5 py-4 hover:bg-indigo-50 transition-colors cursor-pointer" onclick='showModal(\${JSON.stringify(item).replace(/'/g, "\\\\'")})'>\`
        + \`
          <div class="flex items-start justify-between gap-4">
            <div class="flex-1 min-w-0">
              <div class="flex items-center gap-2 mb-1">
                \${issueDate ? \`<span class="text-xs text-gray-400"><i class="fas fa-calendar mr-1"></i>\${issueDate}</span>\` : ''}
                <span class="tag bg-indigo-50 text-indigo-700 border border-indigo-200 text-xs">入札公告</span>
                \${deadlineStatus ? \`<span class="\${deadlineStatus.cls} text-xs px-2 py-0.5 rounded-full">\${deadlineStatus.label}</span>\` : ''}
              </div>
              <p class="text-sm font-medium text-gray-800 leading-snug hover:text-indigo-700">\${escHtml(item.projectName)}</p>
            </div>
            <div class="flex items-center gap-2 flex-shrink-0">
              \${(item.url && item.url.endsWith('.pdf')) ? \`
                <a href="\${escHtml(item.url)}" target="_blank" onclick="event.stopPropagation()"
                   class="text-xs bg-red-50 text-red-600 border border-red-200 px-2.5 py-1 rounded-lg hover:bg-red-100 flex items-center gap-1">
                  <i class="fas fa-file-pdf"></i> PDF
                </a>
              \` : ''}
              <i class="fas fa-chevron-right text-gray-300 text-xs"></i>
            </div>
          </div>
        </div>
      \`;
    });

    html += \`</div></div>
      <div class="mt-4 text-center text-xs text-gray-400">
        <i class="fas fa-info-circle mr-1"></i>
        データ出典: <a href="https://www.jfc.go.jp/n/supply/bid_1.html" target="_blank" class="text-blue-400 hover:underline">日本政策金融公庫 入札情報</a>
      </div>
    \`;

    area.innerHTML = html;
  } catch(e) {
    area.innerHTML = \`<div class="text-center py-16 bg-white rounded-2xl border border-gray-100">
      <i class="fas fa-exclamation-triangle text-yellow-500 text-3xl mb-3"></i>
      <p class="text-gray-600">取得に失敗しました</p>
      <p class="text-xs text-gray-400 mt-1">\${e.message}</p>
    </div>\`;
  }
}

// ========================
// 共通: シンプルAPI呼び出しレンダラー
// ========================
function renderSimpleSourceItems(items, sourceLabel, officialUrl) {
  if (!items || items.length === 0) {
    return \`<div class="text-center py-16 bg-white rounded-2xl border border-gray-100">
      <i class="fas fa-inbox text-gray-300 text-4xl mb-4"></i>
      <p class="text-gray-500 text-lg">案件が見つかりませんでした</p>
      <p class="text-xs text-gray-400 mt-2">現在、公開中の案件がないか、取得できませんでした</p>
      \${officialUrl ? \`<a href="\${escHtml(officialUrl)}" target="_blank" class="mt-4 inline-flex items-center gap-1 text-sm text-blue-600 hover:underline"><i class="fas fa-external-link-alt mr-1"></i>公式サイトで確認する</a>\` : ''}
    </div>\`;
  }
  let html = \`<div class="bg-white rounded-2xl shadow-sm border border-gray-100">
    <div class="p-5 border-b border-gray-100">
      <h3 class="font-bold text-gray-800 flex items-center gap-2">
        <i class="fas fa-list text-blue-500"></i> \${escHtml(sourceLabel)} 調達情報
        <span class="ml-2 text-xs bg-blue-50 text-blue-600 px-2 py-0.5 rounded-full font-normal">\${items.length} 件</span>
      </h3>
    </div>
    <div class="divide-y divide-gray-50">\`;
  items.forEach(item => { html += renderAllItem(item); });
  html += \`</div>
    <div class="p-4 border-t border-gray-100 text-center">
      <a href="\${escHtml(officialUrl)}" target="_blank" class="text-xs text-gray-400 hover:text-blue-500">
        <i class="fas fa-external-link-alt mr-1"></i>データ出典: \${escHtml(officialUrl)}
      </a>
    </div>
  </div>\`;
  return html;
}

// ========================
// UITEC（職業能力開発総合大学校）
// ========================
async function loadUitec() {
  const area = document.getElementById('uitec-result-area');
  const query = document.getElementById('uitec-query').value.trim();
  area.innerHTML = \`<div class="flex justify-center py-16"><div class="text-center"><div class="loading-spinner mx-auto mb-4"></div><p class="text-gray-500 text-sm">職業能力開発総合大学校から調達情報を取得中...</p></div></div>\`;
  try {
    const params = {};
    if (query) params.keyword = query;
    const res = await axios.get('/api/uitec', { params });
    area.innerHTML = renderSimpleSourceItems(res.data.items, '職業能力開発総合大学校', 'https://www.uitec.jeed.go.jp/topics/tender/fp2ce800000000p3.html');
    searchResults = res.data.items || [];
  } catch(e) {
    area.innerHTML = \`<div class="text-center py-16 bg-white rounded-2xl border border-gray-100"><p class="text-gray-600">取得に失敗しました</p><p class="text-xs text-gray-400 mt-1">\${e.message}</p></div>\`;
  }
}

// ========================
// 金融庁
// ========================
async function loadFsa() {
  const area = document.getElementById('fsa-result-area');
  const query = document.getElementById('fsa-query').value.trim();
  area.innerHTML = \`<div class="flex justify-center py-16"><div class="text-center"><div class="loading-spinner mx-auto mb-4"></div><p class="text-gray-500 text-sm">金融庁から調達情報を取得中...</p></div></div>\`;
  try {
    const params = {};
    if (query) params.keyword = query;
    const res = await axios.get('/api/fsa', { params });
    area.innerHTML = renderSimpleSourceItems(res.data.items, '金融庁', 'https://www.fsa.go.jp/choutatu/choutatu_j/nyusatu_menu.html');
    searchResults = res.data.items || [];
  } catch(e) {
    area.innerHTML = \`<div class="text-center py-16 bg-white rounded-2xl border border-gray-100"><p class="text-gray-600">取得に失敗しました</p><p class="text-xs text-gray-400 mt-1">\${e.message}</p></div>\`;
  }
}

// ========================
// 大阪市デジタル統括室
// ========================
async function loadOsaka() {
  const area = document.getElementById('osaka-result-area');
  const query = document.getElementById('osaka-query').value.trim();
  area.innerHTML = \`<div class="flex justify-center py-16"><div class="text-center"><div class="loading-spinner mx-auto mb-4"></div><p class="text-gray-500 text-sm">大阪市デジタル統括室から調達情報を取得中...</p></div></div>\`;
  try {
    const params = {};
    if (query) params.keyword = query;
    const res = await axios.get('/api/osaka', { params });
    area.innerHTML = renderSimpleSourceItems(res.data.items, '大阪市デジタル統括室', 'https://www.city.osaka.lg.jp/templates/gyomuitaku_nyusatsuanken/98-Curr.html');
    searchResults = res.data.items || [];
  } catch(e) {
    area.innerHTML = \`<div class="text-center py-16 bg-white rounded-2xl border border-gray-100"><p class="text-gray-600">取得に失敗しました</p><p class="text-xs text-gray-400 mt-1">\${e.message}</p></div>\`;
  }
}

// ========================
// 北海道情報政策課
// ========================
async function loadHokkaido() {
  const area = document.getElementById('hokkaido-result-area');
  const query = document.getElementById('hokkaido-query').value.trim();
  area.innerHTML = \`<div class="flex justify-center py-16"><div class="text-center"><div class="loading-spinner mx-auto mb-4"></div><p class="text-gray-500 text-sm">北海道 情報政策課から調達情報を取得中...</p></div></div>\`;
  try {
    const params = {};
    if (query) params.keyword = query;
    const res = await axios.get('/api/hokkaido', { params });
    area.innerHTML = renderSimpleSourceItems(res.data.items, '北海道 情報政策課', 'https://www.pref.hokkaido.lg.jp/sm/jsk/a0001/b0002/');
    searchResults = res.data.items || [];
  } catch(e) {
    area.innerHTML = \`<div class="text-center py-16 bg-white rounded-2xl border border-gray-100"><p class="text-gray-600">取得に失敗しました</p><p class="text-xs text-gray-400 mt-1">\${e.message}</p></div>\`;
  }
}

// ========================
// 今治市産業振興課
// ========================
async function loadImabari() {
  const area = document.getElementById('imabari-result-area');
  const query = document.getElementById('imabari-query').value.trim();
  area.innerHTML = \`<div class="flex justify-center py-16"><div class="text-center"><div class="loading-spinner mx-auto mb-4"></div><p class="text-gray-500 text-sm">今治市 産業振興課から調達情報を取得中...</p></div></div>\`;
  try {
    const params = {};
    if (query) params.keyword = query;
    const res = await axios.get('/api/imabari', { params });
    area.innerHTML = renderSimpleSourceItems(res.data.items, '今治市 産業振興課', 'https://www.city.imabari.ehime.jp/sangyou/new.html');
    searchResults = res.data.items || [];
  } catch(e) {
    area.innerHTML = \`<div class="text-center py-16 bg-white rounded-2xl border border-gray-100"><p class="text-gray-600">取得に失敗しました</p><p class="text-xs text-gray-400 mt-1">\${e.message}</p></div>\`;
  }
}

// ========================
// 長野県営業局
// ========================
async function loadNagano() {
  const area = document.getElementById('nagano-result-area');
  const query = document.getElementById('nagano-query').value.trim();
  area.innerHTML = \`<div class="flex justify-center py-16"><div class="text-center"><div class="loading-spinner mx-auto mb-4"></div><p class="text-gray-500 text-sm">長野県 営業局から調達情報を取得中...</p></div></div>\`;
  try {
    const params = {};
    if (query) params.keyword = query;
    const res = await axios.get('/api/nagano', { params });
    area.innerHTML = renderSimpleSourceItems(res.data.items, '長野県 営業局', 'https://www.pref.nagano.lg.jp/eigyo/0415propo.html');
    searchResults = res.data.items || [];
  } catch(e) {
    area.innerHTML = \`<div class="text-center py-16 bg-white rounded-2xl border border-gray-100"><p class="text-gray-600">取得に失敗しました</p><p class="text-xs text-gray-400 mt-1">\${e.message}</p></div>\`;
  }
}

// ========================
// IPA（情報処理推進機構）
// ========================
async function loadIpa() {
  const area = document.getElementById('ipa-result-area');
  const query = document.getElementById('ipa-query').value.trim();
  area.innerHTML = \`<div class="flex justify-center py-16"><div class="text-center"><div class="loading-spinner mx-auto mb-4"></div><p class="text-gray-500 text-sm">IPAから調達情報を取得中...</p></div></div>\`;
  try {
    const params = {};
    if (query) params.keyword = query;
    const res = await axios.get('/api/ipa', { params });
    area.innerHTML = renderSimpleSourceItems(res.data.items, 'IPA 情報処理推進機構', 'https://www.ipa.go.jp/choutatsu/nyusatsu/index.html');
    searchResults = res.data.items || [];
  } catch(e) {
    area.innerHTML = \`<div class="text-center py-16 bg-white rounded-2xl border border-gray-100"><p class="text-gray-600">取得に失敗しました</p><p class="text-xs text-gray-400 mt-1">\${e.message}</p></div>\`;
  }
}

// ========================
// 防災科研（防災科学技術研究所）
// ========================
async function loadBosai() {
  const area = document.getElementById('bosai-result-area');
  const query = document.getElementById('bosai-query').value.trim();
  area.innerHTML = \`<div class="flex justify-center py-16"><div class="text-center"><div class="loading-spinner mx-auto mb-4"></div><p class="text-gray-500 text-sm">防災科研から調達情報を取得中...</p></div></div>\`;
  try {
    const params = {};
    if (query) params.keyword = query;
    const res = await axios.get('/api/bosai', { params });
    area.innerHTML = renderSimpleSourceItems(res.data.items, '防災科学技術研究所', 'https://www.bosai.go.jp/kokai/nyuusatsu/index.html');
    searchResults = res.data.items || [];
  } catch(e) {
    area.innerHTML = \`<div class="text-center py-16 bg-white rounded-2xl border border-gray-100"><p class="text-gray-600">取得に失敗しました</p><p class="text-xs text-gray-400 mt-1">\${e.message}</p></div>\`;
  }
}

// ========================
// 防衛省（内局）
// ========================
async function loadMod() {
  const area = document.getElementById('mod-result-area');
  const query = document.getElementById('mod-query').value.trim();

  area.innerHTML = \`<div class="flex justify-center py-16"><div class="text-center"><div class="loading-spinner mx-auto mb-4"></div><p class="text-gray-500 text-sm">防衛省（内局）から調達情報を取得中...</p></div></div>\`;

  try {
    const params = {};
    if (query) params.query = query;
    const res = await axios.get('/api/mod', { params });
    const data = res.data;

    if (data.error || !data.items || data.items.length === 0) {
      area.innerHTML = \`<div class="text-center py-16 bg-white rounded-2xl border border-gray-100">
        <i class="fas fa-search text-gray-300 text-4xl mb-4"></i>
        <p class="text-gray-500 text-lg">\${data.error ? 'エラーが発生しました' : '案件が見つかりませんでした'}</p>
        \${data.error ? \`<p class="text-xs text-gray-400 mt-1">\${escHtml(data.error)}</p>\` : ''}
        <p class="text-xs text-gray-400 mt-2">
          <a href="https://www.mod.go.jp/j/budget/chotatsu/naikyoku/mitsumori/index.html" target="_blank" class="text-blue-500 hover:underline">公式サイトで直接ご確認ください</a>
        </p>
      </div>\`;
      return;
    }

    let html = \`
      <div class="bg-white rounded-2xl shadow-sm border border-gray-100">
        <div class="p-5 border-b border-gray-100 flex items-center justify-between">
          <h3 class="font-bold text-gray-800 flex items-center gap-2">
            <i class="fas fa-shield-alt text-slate-500"></i>
            見積依頼案件一覧
            <span class="ml-2 text-xs bg-slate-50 text-slate-600 px-2 py-0.5 rounded-full font-normal">
              \${data.totalHits} 件
            </span>
          </h3>
        </div>
        <div class="divide-y divide-gray-50">
    \`;

    data.items.forEach(item => {
      const issueDate = formatDisplayDate(item.cftIssueDate);
      const deadline = formatDisplayDate(item.tenderDeadline);
      html += \`
        <div class="px-5 py-4 hover:bg-slate-50 transition-colors cursor-pointer" onclick='showModal(\${JSON.stringify(item).replace(/'/g, "\\\\'")})'>\`
        + \`
          <div class="flex items-start justify-between gap-4">
            <div class="flex-1 min-w-0">
              <div class="flex items-center gap-2 mb-1">
                \${issueDate ? \`<span class="text-xs text-gray-400"><i class="fas fa-calendar mr-1"></i>\${issueDate}</span>\` : ''}
                <span class="tag bg-slate-50 text-slate-700 border border-slate-200 text-xs">見積合わせ</span>
              </div>
              <p class="font-medium text-gray-800 text-sm leading-snug">\${escHtml(item.projectName)}</p>
              <p class="text-xs text-gray-500 mt-1">\${escHtml(item.organizationName)}</p>
              \${deadline ? \`<p class="text-xs text-orange-500 mt-0.5"><i class="fas fa-clock mr-1"></i>提出期限: \${deadline}</p>\` : ''}
            </div>
            <div class="flex items-center gap-2 flex-shrink-0">
              \${(item.url && item.url.endsWith('.pdf')) ? \`
                <a href="\${escHtml(item.url)}" target="_blank" onclick="event.stopPropagation()"
                   class="text-xs bg-red-50 text-red-600 border border-red-200 px-2.5 py-1 rounded-lg hover:bg-red-100 flex items-center gap-1">
                  <i class="fas fa-file-pdf"></i> PDF
                </a>
              \` : ''}
              <i class="fas fa-chevron-right text-gray-300 text-xs"></i>
            </div>
          </div>
        </div>
      \`;
    });

    html += \`</div></div>
      <div class="mt-4 text-center text-xs text-gray-400">
        <i class="fas fa-info-circle mr-1"></i>
        データ出典: <a href="https://www.mod.go.jp/j/budget/chotatsu/naikyoku/mitsumori/index.html" target="_blank" class="text-blue-400 hover:underline">防衛省 大臣官房会計課 見積依頼</a>
      </div>
    \`;

    area.innerHTML = html;
  } catch(e) {
    area.innerHTML = \`<div class="text-center py-16 bg-white rounded-2xl border border-gray-100">
      <i class="fas fa-exclamation-triangle text-yellow-500 text-3xl mb-3"></i>
      <p class="text-gray-600">取得に失敗しました</p>
      <p class="text-xs text-gray-400 mt-1">\${e.message}</p>
    </div>\`;
  }
}

// ========================
// 防衛省情報本部
// ========================
async function loadModDih() {
  const area = document.getElementById('mod-dih-result-area');
  const query = document.getElementById('mod-dih-query').value.trim();

  area.innerHTML = \`<div class="flex justify-center py-16"><div class="text-center"><div class="loading-spinner mx-auto mb-4"></div><p class="text-gray-500 text-sm">防衛省情報本部から調達情報を取得中...</p></div></div>\`;

  try {
    const params = {};
    if (query) params.query = query;
    const res = await axios.get('/api/mod-dih', { params });
    const data = res.data;

    if (data.error || !data.items || data.items.length === 0) {
      area.innerHTML = \`<div class="text-center py-16 bg-white rounded-2xl border border-gray-100">
        <i class="fas fa-search text-gray-300 text-4xl mb-4"></i>
        <p class="text-gray-500 text-lg">\${data.error ? 'エラーが発生しました' : '案件が見つかりませんでした'}</p>
        \${data.error ? \`<p class="text-xs text-gray-400 mt-1">\${escHtml(data.error)}</p>\` : ''}
        <p class="text-xs text-gray-400 mt-2">
          <a href="https://www.mod.go.jp/dih/supply/open-r8.html" target="_blank" class="text-blue-500 hover:underline">公式サイトで直接ご確認ください</a>
        </p>
      </div>\`;
      return;
    }

    let html = \`
      <div class="bg-white rounded-2xl shadow-sm border border-gray-100">
        <div class="p-5 border-b border-gray-100 flex items-center justify-between">
          <h3 class="font-bold text-gray-800 flex items-center gap-2">
            <i class="fas fa-satellite-dish text-sky-500"></i>
            見積依頼案件一覧
            <span class="ml-2 text-xs bg-sky-50 text-sky-600 px-2 py-0.5 rounded-full font-normal">
              \${data.totalHits} 件
            </span>
          </h3>
        </div>
        <div class="divide-y divide-gray-50">
    \`;

    data.items.forEach(item => {
      const deadline = formatDisplayDate(item.tenderDeadline);
      html += \`
        <div class="px-5 py-4 hover:bg-sky-50 transition-colors cursor-pointer" onclick='showModal(\${JSON.stringify(item).replace(/'/g, "\\\\'")})'>\`
        + \`
          <div class="flex items-start justify-between gap-4">
            <div class="flex-1 min-w-0">
              <div class="flex items-center gap-2 mb-1">
                \${deadline ? \`<span class="text-xs text-orange-500"><i class="fas fa-clock mr-1"></i>見積期限: \${deadline}</span>\` : ''}
                <span class="tag bg-sky-50 text-sky-700 border border-sky-200 text-xs">見積合わせ</span>
              </div>
              <p class="font-medium text-gray-800 text-sm leading-snug">\${escHtml(item.projectName)}</p>
              <p class="text-xs text-gray-500 mt-1">\${escHtml(item.organizationName)}</p>
            </div>
            <div class="flex items-center gap-2 flex-shrink-0">
              \${(item.url && item.url.endsWith('.pdf')) ? \`
                <a href="\${escHtml(item.url)}" target="_blank" onclick="event.stopPropagation()"
                   class="text-xs bg-red-50 text-red-600 border border-red-200 px-2.5 py-1 rounded-lg hover:bg-red-100 flex items-center gap-1">
                  <i class="fas fa-file-pdf"></i> PDF
                </a>
              \` : ''}
              <i class="fas fa-chevron-right text-gray-300 text-xs"></i>
            </div>
          </div>
        </div>
      \`;
    });

    html += \`</div></div>
      <div class="mt-4 text-center text-xs text-gray-400">
        <i class="fas fa-info-circle mr-1"></i>
        データ出典: <a href="https://www.mod.go.jp/dih/supply/open-r8.html" target="_blank" class="text-blue-400 hover:underline">防衛省情報本部 随意契約見積依頼</a>
      </div>
    \`;

    area.innerHTML = html;
  } catch(e) {
    area.innerHTML = \`<div class="text-center py-16 bg-white rounded-2xl border border-gray-100">
      <i class="fas fa-exclamation-triangle text-yellow-500 text-3xl mb-3"></i>
      <p class="text-gray-600">取得に失敗しました</p>
      <p class="text-xs text-gray-400 mt-1">\${e.message}</p>
    </div>\`;
  }
}

// ========================
// 全ソース一括検索
// ========================
async function loadAll() {
  const area = document.getElementById('all-result-area');
  const query = document.getElementById('all-query').value.trim();
  const useSrcKkj = document.getElementById('src-kkj').checked;
  const useSrcKkp = document.getElementById('src-kkp').checked;
  const useSrcPfa = document.getElementById('src-pfa').checked;
  const useSrcJeed = document.getElementById('src-jeed').checked;
  const useSrcJfc = document.getElementById('src-jfc').checked;
  const useSrcFsa = document.getElementById('src-fsa').checked;
  const useSrcUitec = document.getElementById('src-uitec').checked;
  const useSrcOsaka = document.getElementById('src-osaka').checked;
  const useSrcHokkaido = document.getElementById('src-hokkaido').checked;
  const useSrcImabari = document.getElementById('src-imabari').checked;
  const useSrcNagano = document.getElementById('src-nagano').checked;
  const useSrcIpa = document.getElementById('src-ipa').checked;
  const useSrcBosai = document.getElementById('src-bosai').checked;

  if (!useSrcKkj && !useSrcKkp && !useSrcPfa && !useSrcJeed && !useSrcJfc && !useSrcFsa && !useSrcUitec && !useSrcOsaka && !useSrcHokkaido && !useSrcImabari && !useSrcNagano && !useSrcIpa && !useSrcBosai) {
    area.innerHTML = \`<div class="text-center py-8 bg-white rounded-2xl border border-gray-100">
      <p class="text-gray-500">検索対象ソースを1つ以上選択してください</p>
    </div>\`;
    return;
  }

  area.innerHTML = \`<div class="flex justify-center py-16"><div class="text-center"><div class="loading-spinner mx-auto mb-4"></div><p class="text-gray-500 text-sm">全ソースを横断検索中...</p></div></div>\`;

  try {
    const sources = [];
    if (useSrcKkj) sources.push('kkj');
    if (useSrcKkp) sources.push('kyoukaikenpo');
    if (useSrcPfa) sources.push('pfa');
    if (useSrcJeed) sources.push('jeed');
    if (useSrcJfc) sources.push('jfc');
    if (useSrcFsa) sources.push('fsa');
    if (useSrcUitec) sources.push('uitec');
    if (useSrcOsaka) sources.push('osaka');
    if (useSrcHokkaido) sources.push('hokkaido');
    if (useSrcImabari) sources.push('imabari');
    if (useSrcNagano) sources.push('nagano');
    if (useSrcIpa) sources.push('ipa');
    if (useSrcBosai) sources.push('bosai');

    const allSfName = document.getElementById('all-sf-name')?.checked;
    const allSfDesc = document.getElementById('all-sf-desc')?.checked;
    const allSfOrg  = document.getElementById('all-sf-org')?.checked;
    const searchFields = [allSfName && 'name', allSfDesc && 'desc', allSfOrg && 'org'].filter(Boolean).join(',') || 'name';

    const params = { sources: sources.join(','), searchFields };
    if (query) params.keyword = query;

    const res = await axios.get('/api/search-all', { params });
    const data = res.data;

    if (!data.items || data.items.length === 0) {
      area.innerHTML = \`<div class="text-center py-16 bg-white rounded-2xl border border-gray-100">
        <i class="fas fa-search text-gray-300 text-4xl mb-4"></i>
        <p class="text-gray-500 text-lg">案件が見つかりませんでした</p>
        <p class="text-xs text-gray-400 mt-2">キーワードを変更するか、検索対象ソースを確認してください</p>
      </div>\`;
      return;
    }

    // ソース別カウント
    const sourceCounts = {};
    data.items.forEach(item => {
      const src = item.source || '不明';
      sourceCounts[src] = (sourceCounts[src] || 0) + 1;
    });

    const sourceColors = {
      '官公需ポータル': 'bg-blue-50 text-blue-700 border-blue-200',
      '協会けんぽ (公開中)': 'bg-rose-50 text-rose-700 border-rose-200',
      '協会けんぽ': 'bg-rose-50 text-rose-700 border-rose-200',
      '企業年金連合会': 'bg-amber-50 text-amber-700 border-amber-200',
    };

    let summaryHtml = '<div class="flex flex-wrap gap-2 mb-4">';
    for (const [src, cnt] of Object.entries(sourceCounts)) {
      const colorCls = Object.entries(sourceColors).find(([k]) => src.includes(k.split(' ')[0]))?.[1] || 'bg-gray-50 text-gray-700 border-gray-200';
      summaryHtml += \`<span class="tag border \${colorCls} px-3 py-1 text-xs">\${escHtml(src)}: \${cnt}件</span>\`;
    }
    summaryHtml += '</div>';

    let html = \`
      <div class="bg-white rounded-2xl shadow-sm border border-gray-100">
        <div class="p-5 border-b border-gray-100">
          <h3 class="font-bold text-gray-800 flex items-center gap-2 mb-3">
            <i class="fas fa-layer-group text-indigo-500"></i>
            一括検索結果
            <span class="ml-2 text-xs bg-indigo-50 text-indigo-600 px-2 py-0.5 rounded-full font-normal">
              計 \${data.totalHits} 件
            </span>
          </h3>
          \${summaryHtml}
          \${data.errors ? \`<div class="text-xs text-orange-600 bg-orange-50 border border-orange-200 rounded-lg px-3 py-2">
            <i class="fas fa-exclamation-circle mr-1"></i>一部ソースで取得エラーが発生しました（取得できたデータのみ表示しています）
          </div>\` : ''}
        </div>
        <div id="result-list" class="divide-y divide-gray-50">
    \`;

    data.items.forEach(item => {
      html += renderAllItem(item);
    });

    html += \`</div></div>\`;
    area.innerHTML = html;
    searchResults = data.items;
  } catch(e) {
    area.innerHTML = \`<div class="text-center py-16 bg-white rounded-2xl border border-gray-100">
      <i class="fas fa-exclamation-triangle text-yellow-500 text-3xl mb-3"></i>
      <p class="text-gray-600">一括検索に失敗しました</p>
      <p class="text-xs text-gray-400 mt-1">\${e.message}</p>
    </div>\`;
  }
}

function renderAllItem(item) {
  const catBadge = getCategoryBadge(item.category);
  const issueDate = formatDisplayDate(item.cftIssueDate);
  const deadline = formatDisplayDate(item.tenderSubmissionDeadline);
  const deadlineWarning = isDeadlineSoon(item.tenderSubmissionDeadline);

  const sourceColors = {
    '官公需ポータル': 'bg-blue-50 text-blue-600',
    '協会けんぽ': 'bg-rose-50 text-rose-600',
    '企業年金連合会': 'bg-amber-50 text-amber-600',
  };
  const src = item.source || '';
  const srcColorCls = Object.entries(sourceColors).find(([k]) => src.includes(k.split(' ')[0]))?.[1] || 'bg-gray-50 text-gray-600';
  const srcBadge = src ? \`<span class="tag \${srcColorCls} text-xs">\${escHtml(src)}</span>\` : '';

  return \`
    <div class="result-row px-6 py-4 cursor-pointer" onclick='showModal(\${JSON.stringify(item).replace(/'/g, "\\\\'")})'>\`
    + \`
      <div class="flex items-start justify-between gap-4">
        <div class="flex-1 min-w-0">
          <div class="flex flex-wrap items-center gap-2 mb-2">
            \${srcBadge}
            \${catBadge}
            \${item.procedureType ? \`<span class="tag bg-gray-100 text-gray-600">\${escHtml(item.procedureType)}</span>\` : ''}
            \${deadlineWarning ? '<span class="tag bg-red-100 text-red-600"><i class="fas fa-fire-alt mr-1"></i>締切間近</span>' : ''}
          </div>
          <h4 class="text-sm font-semibold text-gray-800 leading-snug mb-2 hover:text-blue-600">
            \${escHtml(item.projectName || '（案件名なし）')}
          </h4>
          <div class="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-gray-500">
            \${item.organizationName ? \`<span><i class="fas fa-building mr-1 text-gray-400"></i>\${escHtml(item.organizationName)}</span>\` : ''}
            \${issueDate ? \`<span><i class="fas fa-calendar mr-1 text-gray-400"></i>公告: \${issueDate}</span>\` : ''}
            \${deadline ? \`<span class="\${deadlineWarning ? 'text-red-500 font-medium' : ''}"><i class="fas fa-clock mr-1 text-gray-400"></i>締切: \${deadline}</span>\` : ''}
          </div>
        </div>
        <div class="flex-shrink-0">
          <i class="fas fa-chevron-right text-gray-300 text-sm mt-1"></i>
        </div>
      </div>
    </div>
  \`;
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

// ========================
// 募集期間ステータス
// ========================
function getDeadlineField(item) {
  // 締切日として使うフィールド（優先順位順）
  return item.tenderSubmissionDeadline || item.tenderDeadline || '';
}

function getDeadlineStatus(item) {
  // status: 'open' | 'warn' | 'urgent' | 'closed' | 'unknown'
  const deadlineStr = getDeadlineField(item);
  if (!deadlineStr) return { status: 'unknown', diffDays: null };
  const d = new Date(deadlineStr);
  if (isNaN(d.getTime())) return { status: 'unknown', diffDays: null };
  const now = new Date();
  const diffMs = d - now;
  const diffDays = diffMs / (1000 * 60 * 60 * 24);
  if (diffDays < 0) return { status: 'closed', diffDays };
  if (diffDays < 3) return { status: 'urgent', diffDays };
  if (diffDays < 7) return { status: 'warn', diffDays };
  return { status: 'open', diffDays };
}

function renderDeadlineBadge(item) {
  const { status, diffDays } = getDeadlineStatus(item);
  if (status === 'unknown') {
    return '<span class="tag bg-gray-100 text-gray-400"><i class="fas fa-question-circle mr-1"></i>期限情報なし</span>';
  }
  if (status === 'closed') {
    return '<span class="tag bg-gray-200 text-gray-500"><i class="fas fa-lock mr-1"></i>締切済み</span>';
  }
  if (status === 'urgent') {
    const hrs = Math.floor(diffDays * 24);
    const label = hrs < 24 ? '残り' + hrs + '時間' : '残り' + Math.ceil(diffDays) + '日';
    return \`<span class="tag bg-red-100 text-red-600"><i class="fas fa-fire-alt mr-1"></i>\${label}</span>\`;
  }
  if (status === 'warn') {
    return \`<span class="tag bg-yellow-100 text-yellow-700"><i class="fas fa-exclamation-triangle mr-1"></i>残り\${Math.ceil(diffDays)}日</span>\`;
  }
  // open
  return '<span class="tag bg-green-100 text-green-700"><i class="fas fa-check-circle mr-1"></i>募集中</span>';
}

function isItemClosed(item) {
  const { status } = getDeadlineStatus(item);
  return status === 'closed';
}

function escHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// Enterキーで検索
document.getElementById('s-query').addEventListener('keypress', e => { if (e.key === 'Enter') doSearch(); });
document.getElementById('s-orgname').addEventListener('keypress', e => { if (e.key === 'Enter') doSearch(); });

// ========================
// 通知設定
// ========================
async function loadNotifyStatus() {
  const area = document.getElementById('notify-status-area');
  try {
    const res = await axios.get('/api/notify-status');
    const d = res.data;
    const configured = d.resendConfigured;

    area.innerHTML = \`
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div class="bg-gray-50 rounded-xl p-4">
          <p class="text-xs font-semibold text-gray-500 uppercase mb-2">メール送信サービス (Resend)</p>
          <div class="flex items-center gap-2">
            <span class="w-2.5 h-2.5 rounded-full \${configured ? 'bg-green-400' : 'bg-red-400'}"></span>
            <span class="text-sm font-medium text-gray-700">\${configured ? '✅ 設定済み' : '❌ 未設定'}</span>
          </div>
        </div>
        <div class="bg-gray-50 rounded-xl p-4">
          <p class="text-xs font-semibold text-gray-500 uppercase mb-2">監視キーワード</p>
          <div class="flex flex-wrap gap-1.5">
            \${(d.notifyKeywords || []).map(kw => \`<span class="tag bg-violet-100 text-violet-700 px-2 py-0.5">\${escHtml(kw)}</span>\`).join('')}
          </div>
        </div>
        <div class="bg-gray-50 rounded-xl p-4">
          <p class="text-xs font-semibold text-gray-500 uppercase mb-2">通知先メールアドレス</p>
          <div class="space-y-1">
            \${(d.notifyEmails || []).map(e => \`<p class="text-sm text-gray-700"><i class="fas fa-envelope mr-2 text-gray-400"></i>\${escHtml(e)}</p>\`).join('')}
          </div>
        </div>
        <div class="bg-gray-50 rounded-xl p-4">
          <p class="text-xs font-semibold text-gray-500 uppercase mb-2">自動チェック時刻</p>
          <p class="text-sm font-medium text-gray-700"><i class="fas fa-clock mr-2 text-gray-400"></i>\${d.schedule}</p>
        </div>
      </div>
    \`;
  } catch(e) {
    area.innerHTML = \`<p class="text-sm text-red-500">設定の読み込みに失敗しました: \${e.message}</p>\`;
  }
}

async function runNotifyCheck() {
  const btn = document.querySelector('[onclick="runNotifyCheck()"]');
  const statusEl = document.getElementById('notify-run-status');
  const resultEl = document.getElementById('notify-run-result');

  btn.disabled = true;
  statusEl.textContent = 'チェック中...';
  statusEl.className = 'text-sm text-blue-500';
  resultEl.classList.add('hidden');

  try {
    const res = await axios.get('/api/notify-check?secret=bid-notify-2024', { timeout: 60000 });
    const d = res.data;

    let html = \`<div class="bg-green-50 border border-green-200 rounded-xl p-4">
      <p class="font-semibold text-green-700 mb-3"><i class="fas fa-check-circle mr-2"></i>チェック完了</p>
      <div class="space-y-2 text-sm text-gray-700">
        <p><strong>チェック総件数:</strong> \${(d.checkedTotal || 0).toLocaleString()} 件</p>\`;

    const keywords = Object.keys(d.newItems || {});
    for (const kw of keywords) {
      const cnt = d.newItems[kw];
      const sent = d.mailSent?.[kw];
      html += \`<p>
        <strong>「\${escHtml(kw)}」新着:</strong> \${cnt} 件
        \${cnt > 0
          ? (sent ? '<span class="text-green-600 ml-2"><i class="fas fa-paper-plane mr-1"></i>メール送信済み</span>'
                  : '<span class="text-orange-500 ml-2"><i class="fas fa-exclamation-circle mr-1"></i>送信スキップ</span>')
          : '<span class="text-gray-400 ml-2">（新着なし）</span>'}
      </p>\`;
    }

    if (d.errors && d.errors.length > 0) {
      html += \`<div class="mt-2 p-2 bg-yellow-50 rounded text-xs text-yellow-700">
        <i class="fas fa-exclamation-triangle mr-1"></i>警告: \${d.errors.join(' / ')}
      </div>\`;
    }

    html += \`<p class="text-xs text-gray-400 mt-2">実行時刻: \${new Date(d.timestamp).toLocaleString('ja-JP')}</p>
      </div></div>\`;

    resultEl.innerHTML = html;
    resultEl.classList.remove('hidden');
    statusEl.textContent = '完了';
    statusEl.className = 'text-sm text-green-600';
  } catch(e) {
    resultEl.innerHTML = \`<div class="bg-red-50 border border-red-200 rounded-xl p-4 text-sm text-red-600">
      <i class="fas fa-times-circle mr-2"></i>エラー: \${e.message}
    </div>\`;
    resultEl.classList.remove('hidden');
    statusEl.textContent = 'エラー';
    statusEl.className = 'text-sm text-red-500';
  } finally {
    btn.disabled = false;
  }
}

// ========================
// 初期表示（認証チェック）
// ========================
if (isLoggedIn()) {
  showApp();
  updateBookmarkBadge();
  loadDashboard();
} else {
  showLogin();
}
</script>
</body>
</html>`
}

// ============================================================
// キーワード通知チェック API
// ============================================================

// 既出案件IDを保存するグローバルストア（サーバーメモリ）
// Cloudflare Pages本番ではKVを使用するためリクエスト間でリセットされるが、
// サンドボックスのPM2プロセスでは永続する
const seenIdsStore: Map<string, Set<string>> = new Map()

function getSeenIds(keyword: string): Set<string> {
  if (!seenIdsStore.has(keyword)) {
    seenIdsStore.set(keyword, new Set())
  }
  return seenIdsStore.get(keyword)!
}

// Resend経由でメール送信
async function sendEmailViaResend(
  apiKey: string,
  to: string[],
  subject: string,
  html: string
): Promise<{ ok: boolean; error?: string }> {
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: '入札DX通知 <onboarding@resend.dev>',
        to,
        subject,
        html,
      }),
    })
    if (!res.ok) {
      const body = await res.text()
      return { ok: false, error: `Resend API error ${res.status}: ${body}` }
    }
    return { ok: true }
  } catch (e) {
    return { ok: false, error: String(e) }
  }
}

// メール本文HTMLを生成
function buildEmailHtml(keyword: string, items: any[]): string {
  const rows = items.map(item => {
    const date = item.cftIssueDate ? item.cftIssueDate.substring(0, 10) : '不明'
    const source = item.source || item.organizationName || '不明'
    const procType = item.procedureType || ''
    const url = item.url || ''
    return `
      <tr>
        <td style="padding:10px 12px;border-bottom:1px solid #e5e7eb;font-size:13px;color:#374151;">${date}</td>
        <td style="padding:10px 12px;border-bottom:1px solid #e5e7eb;font-size:13px;">
          <a href="${url}" target="_blank" style="color:#2563eb;text-decoration:none;font-weight:500;">${item.projectName || '（案件名なし）'}</a>
        </td>
        <td style="padding:10px 12px;border-bottom:1px solid #e5e7eb;font-size:12px;color:#6b7280;">${source}</td>
        <td style="padding:10px 12px;border-bottom:1px solid #e5e7eb;font-size:12px;color:#6b7280;">${procType}</td>
      </tr>`
  }).join('')

  const now = new Date().toLocaleString('ja-JP', { timeZone: 'Asia/Tokyo' })

  return `<!DOCTYPE html>
<html lang="ja">
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f9fafb;font-family:'Helvetica Neue',Arial,sans-serif;">
  <div style="max-width:700px;margin:32px auto;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">

    <!-- ヘッダー -->
    <div style="background:linear-gradient(135deg,#1e3a5f,#2563eb);padding:24px 32px;">
      <h1 style="margin:0;color:#ffffff;font-size:20px;font-weight:700;">
        🔔 入札DX 新着案件通知
      </h1>
      <p style="margin:6px 0 0;color:#bfdbfe;font-size:13px;">キーワード「${keyword}」の新着案件が見つかりました</p>
    </div>

    <!-- 件数サマリー -->
    <div style="padding:20px 32px;background:#eff6ff;border-bottom:1px solid #dbeafe;">
      <p style="margin:0;font-size:15px;color:#1d4ed8;font-weight:600;">
        📋 新着 ${items.length} 件 ／ チェック日時: ${now}
      </p>
    </div>

    <!-- 案件テーブル -->
    <div style="padding:24px 32px;">
      <table style="width:100%;border-collapse:collapse;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;">
        <thead>
          <tr style="background:#f3f4f6;">
            <th style="padding:10px 12px;text-align:left;font-size:12px;color:#6b7280;font-weight:600;width:90px;">公告日</th>
            <th style="padding:10px 12px;text-align:left;font-size:12px;color:#6b7280;font-weight:600;">案件名</th>
            <th style="padding:10px 12px;text-align:left;font-size:12px;color:#6b7280;font-weight:600;width:120px;">発注機関</th>
            <th style="padding:10px 12px;text-align:left;font-size:12px;color:#6b7280;font-weight:600;width:100px;">種別</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>

    <!-- フッター -->
    <div style="padding:16px 32px 24px;border-top:1px solid #f3f4f6;">
      <p style="margin:0;font-size:12px;color:#9ca3af;line-height:1.6;">
        このメールは 入札DX 自動通知システム から送信されています。<br>
        データ出典: 官公需情報ポータルサイト (kkj.go.jp)・全国健康保険協会・企業年金連合会
      </p>
    </div>

  </div>
</body>
</html>`
}

// 通知チェック本体ロジック
async function runNotifyCheck(env: {
  RESEND_API_KEY?: string
  NOTIFY_EMAILS?: string
  NOTIFY_KEYWORDS?: string
}): Promise<{
  checked: number
  newItems: Record<string, any[]>
  sent: Record<string, boolean>
  errors: string[]
}> {
  const apiKey = env.RESEND_API_KEY || ''
  const emails = (env.NOTIFY_EMAILS || '').split(',').map(s => s.trim()).filter(Boolean)
  const keywords = (env.NOTIFY_KEYWORDS || '動画制作,研修').split(',').map(s => s.trim()).filter(Boolean)

  const errors: string[] = []
  const newItems: Record<string, any[]> = {}
  const sent: Record<string, boolean> = {}
  let totalChecked = 0

  // 全ソースから全案件を取得
  const allItems: any[] = []

  // 官公需ポータル（キーワードごとに検索）
  for (const kw of keywords) {
    try {
      const params = new URLSearchParams({ Query: kw, Count: '50' })
      const res = await fetch(`http://www.kkj.go.jp/api/?${params.toString()}`, {
        headers: { 'User-Agent': 'BidSearchApp/1.0' }
      })
      const xml = await res.text()
      const parsed = parseKkjXml(xml)
      ;(parsed.items || []).forEach((item: any) => {
        item.source = '官公需ポータル'
        item._matchKeyword = kw
        allItems.push(item)
      })
      totalChecked += parsed.totalHits || 0
    } catch (e) {
      errors.push(`官公需ポータル[${kw}]: ${String(e)}`)
    }
  }

  // 協会けんぽ
  try {
    const res = await fetch('https://www.kyoukaikenpo.or.jp/disclosure/procurement/', {
      headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' }
    })
    const html = await res.text()
    const items = parseKyoukaikenpoHtml(html, '協会けんぽ')
    items.forEach((item: any) => allItems.push(item))
    totalChecked += items.length
  } catch (e) {
    errors.push(`協会けんぽ: ${String(e)}`)
  }

  // 企業年金連合会
  try {
    const res = await fetch('https://www.pfa.or.jp/chotatsu/ichiran/index.html', {
      headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' }
    })
    const html = await res.text()
    const items = scrapePfa(html)
    items.forEach((item: any) => allItems.push(item))
    totalChecked += items.length
  } catch (e) {
    errors.push(`企業年金連合会: ${String(e)}`)
  }

  // JEED（高齢・障害・求職者雇用支援機構）
  try {
    const res = await fetch('https://www.jeed.go.jp/jeed/information/honbu/chotatsu_buppin.html', {
      headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' }
    })
    const html = await res.text()
    const items = scrapeJeed(html)
    items.forEach((item: any) => allItems.push(item))
    totalChecked += items.length
  } catch (e) {
    errors.push(`JEED: ${String(e)}`)
  }

  // JFC（日本政策金融公庫）
  try {
    const res = await fetch('https://www.jfc.go.jp/n/supply/bid_1.html', {
      headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' }
    })
    const html = await res.text()
    const items = scrapeJfc(html)
    items.forEach((item: any) => allItems.push(item))
    totalChecked += items.length
  } catch (e) {
    errors.push(`JFC: ${String(e)}`)
  }

  // 金融庁
  try {
    const res = await fetch('https://www.fsa.go.jp/choutatu/choutatu_j/nyusatu_menu.html', {
      headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' }
    })
    const html = await res.text()
    const items = scrapeFsa(html)
    items.forEach((item: any) => allItems.push(item))
    totalChecked += items.length
  } catch (e) {
    errors.push(`金融庁: ${String(e)}`)
  }

  // UITEC（職業能力開発総合大学校）
  try {
    const pages = [
      'https://www.uitec.jeed.go.jp/topics/tender/fp2ce800000000p3.html',
      'https://www.uitec.jeed.go.jp/topics/tender/ka7cok0000005u3v.html',
    ]
    for (const url of pages) {
      try {
        const r = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' } })
        if (r.ok) {
          const items = scrapeUitec(await r.text())
          items.forEach((item: any) => allItems.push(item))
          totalChecked += items.length
        }
      } catch (_) {}
    }
  } catch (e) {
    errors.push(`UITEC: ${String(e)}`)
  }

  // 大阪市デジタル統括室
  try {
    const res = await fetch('https://www.city.osaka.lg.jp/templates/gyomuitaku_nyusatsuanken/98-Curr.html', {
      headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' }
    })
    const html = await res.text()
    const items = scrapeOsakaCity(html)
    items.forEach((item: any) => allItems.push(item))
    totalChecked += items.length
  } catch (e) {
    errors.push(`大阪市: ${String(e)}`)
  }

  // 北海道情報政策課
  try {
    const res = await fetch('https://www.pref.hokkaido.lg.jp/sm/jsk/a0001/b0002/', {
      headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' }
    })
    const html = await res.text()
    const items = scrapeHokkaido(html)
    items.forEach((item: any) => allItems.push(item))
    totalChecked += items.length
  } catch (e) {
    errors.push(`北海道: ${String(e)}`)
  }

  // 今治市産業振興課
  try {
    const res = await fetch('https://www.city.imabari.ehime.jp/sangyou/new.html', {
      headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' }
    })
    const html = await res.text()
    const items = scrapeImabari(html)
    items.forEach((item: any) => allItems.push(item))
    totalChecked += items.length
  } catch (e) {
    errors.push(`今治市: ${String(e)}`)
  }

  // 長野県営業局
  try {
    const res = await fetch('https://www.pref.nagano.lg.jp/eigyo/0415propo.html', {
      headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' }
    })
    const html = await res.text()
    const items = scrapeNagano(html)
    items.forEach((item: any) => allItems.push(item))
    totalChecked += items.length
  } catch (e) {
    errors.push(`長野県: ${String(e)}`)
  }

  // IPA（情報処理推進機構）
  try {
    const res = await fetch('https://www.ipa.go.jp/choutatsu/nyusatsu/2026/index.html', {
      headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' }
    })
    const html = await res.text()
    const items = scrapeIpa(html)
    items.forEach((item: any) => allItems.push(item))
    totalChecked += items.length
  } catch (e) {
    errors.push(`IPA: ${String(e)}`)
  }

  // 防災科研
  try {
    const res = await fetch('https://www.bosai.go.jp/kokai/nyuusatsu/index.html', {
      headers: { 'User-Agent': 'Mozilla/5.0 BidSearchApp/1.0' }
    })
    const html = await res.text()
    const items = scrapeBosai(html)
    items.forEach((item: any) => allItems.push(item))
    totalChecked += items.length
  } catch (e) {
    errors.push(`防災科研: ${String(e)}`)
  }

  // キーワードフィルタリング & 新着判定（案件名＋説明文＋機関名）
  for (const kw of keywords) {
    const matched = allItems.filter(item =>
      (item.projectName || '').includes(kw) ||
      (item.projectDescription || '').includes(kw) ||
      (item.organizationName || '').includes(kw)
    )

    const seenIds = getSeenIds(kw)
    const freshItems = matched.filter(item => {
      const id = item.resultId || item.url || item.projectName || ''
      return id && !seenIds.has(id)
    })

    newItems[kw] = freshItems

    // 既出IDを更新
    matched.forEach(item => {
      const id = item.resultId || item.url || item.projectName || ''
      if (id) seenIds.add(id)
    })
  }

  // メール送信（新着がある場合のみ）
  if (apiKey && emails.length > 0) {
    for (const kw of keywords) {
      const items = newItems[kw] || []
      if (items.length === 0) {
        sent[kw] = false
        continue
      }
      const subject = `【入札DX】「${kw}」新着案件 ${items.length}件`
      const html = buildEmailHtml(kw, items)
      const result = await sendEmailViaResend(apiKey, emails, subject, html)
      sent[kw] = result.ok
      if (!result.ok) errors.push(`メール送信[${kw}]: ${result.error}`)
    }
  }

  return { checked: totalChecked, newItems, sent, errors }
}

// ===========================
// POST /api/notify-check
// 手動テスト & PM2 cronから呼び出すエンドポイント
// ===========================
app.get('/api/notify-check', async (c) => {
  const secret = c.req.query('secret') || ''
  const envSecret = c.env.NOTIFY_SECRET || 'bid-notify-2024'
  if (secret !== envSecret) {
    return c.json({ error: '認証エラー: secretパラメータが必要です' }, 401)
  }

  const result = await runNotifyCheck({
    RESEND_API_KEY: c.env.RESEND_API_KEY || '',
    NOTIFY_EMAILS: c.env.NOTIFY_EMAILS || 'contents@onsuku.jp',
    NOTIFY_KEYWORDS: c.env.NOTIFY_KEYWORDS || '動画制作,研修',
  })

  const summary: Record<string, number> = {}
  for (const [kw, items] of Object.entries(result.newItems)) {
    summary[kw] = (items as any[]).length
  }

  return c.json({
    status: 'ok',
    checkedTotal: result.checked,
    newItems: summary,
    mailSent: result.sent,
    errors: result.errors.length > 0 ? result.errors : undefined,
    timestamp: new Date().toISOString(),
  })
})

// ===========================
// GET /api/notify-status
// 通知設定の確認用（設定が正しいか確認）
// ===========================
app.get('/api/notify-status', async (c) => {
  const apiKey = c.env.RESEND_API_KEY || ''
  const emails = c.env.NOTIFY_EMAILS || ''
  const keywords = c.env.NOTIFY_KEYWORDS || ''

  return c.json({
    resendConfigured: !!apiKey,
    notifyEmails: emails ? emails.split(',').map(s => s.trim()) : [],
    notifyKeywords: keywords ? keywords.split(',').map(s => s.trim()) : [],
    schedule: '毎日 11:00 (JST)',
    lastCheck: '未実施（初回チェック前）',
  })
})

// =============================
// フロントエンド HTML配信
// =============================
app.get('/', (c) => {
  return c.html(renderHTML())
})

// SPA: /以外のパスもHTMLを返す（ただし/api/*は上のルートで処理済み）
app.notFound((c) => {
  // APIパスは404のままにする
  if (c.req.path.startsWith('/api/')) {
    return c.json({ error: 'Not Found', path: c.req.path }, 404)
  }
  return c.html(renderHTML())
})

export default app
