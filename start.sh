#!/bin/bash
# 启动命令（生产环境）
# ADMIN_SECRET=你的管理员密钥 uvicorn server:app --host 0.0.0.0 --port 8000
uvicorn server:app --host 0.0.0.0 --port 8000
