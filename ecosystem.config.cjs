module.exports = {
  apps: [
    {
      name: 'webapp',
      script: 'npx',
      args: 'wrangler pages dev dist --ip 0.0.0.0 --port 3000',
      env: {
        NODE_ENV: 'development',
        PORT: 3000
      },
      watch: false,
      instances: 1,
      exec_mode: 'fork'
    },
    {
      // 毎日11:00 JSTにキーワード通知チェックを実行
      // cron_restart: PM2のcron機能でスケジュール実行
      name: 'notify-cron',
      script: 'node',
      args: '-e "require(\'https\').get(\'https://3000-ixlmbkfbacwqfrnn9dxgr-ecea8f22.sandbox.novita.ai/api/notify-check?secret=bid-notify-2024\', (r)=>{let d=\'\';r.on(\'data\',c=>d+=c);r.on(\'end\',()=>console.log(\'[notify-cron]\',new Date().toISOString(),d))}).on(\'error\',(e)=>console.error(\'[notify-cron] error:\',e.message))"',
      cron_restart: '0 2 * * *',  // UTC 02:00 = JST 11:00
      watch: false,
      autorestart: false,
      instances: 1,
      exec_mode: 'fork'
    }
  ]
}
