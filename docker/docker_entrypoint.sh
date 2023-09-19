#!/bin/sh
set -e

#获取配置的自定义参数
if [ -n "$1" ]; then
  run_cmd=$1
fi

(
if [ -f "/dm/pull.lock" ]; then
  echo "存在更新锁定文件，跳过git pull操作..."
else
  echo "设定远程仓库地址..."
  cd /dm
  git remote set-url origin "$REPO_URL"
  git reset --hard
  echo "git pull拉取最新代码..."
  git -C /dm pull --rebase
  echo "npm install 安装最新依赖"
  npm install --prefix /dm
fi
) || exit 0


echo "--------------------------------------------------开启node service---------------------------------------------------"

echo "启动node service服务..."

pm2 start /dm/ecosystem.config.js --no-daemon

echo "node service服务任务执行结束。"


