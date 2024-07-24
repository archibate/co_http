# co_http

之前同学反映，小彭老师的 co_async 协程看不懂，C++20 不支持、Linux 版本低等问题。

为了便于同学们专心学习网络知识，小彭老师特意从零开始研发的一款教学用，基于 C++17 回调函数的异步 HTTP 服务器。

最新一期视频中，我们实现了一个基于长轮询的异步聊天服务器。

![](http://142857.red/files/screenshotchatserver.png)

编译和运行：

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target chat_server
cd build
./chat_server
```

> 小彭老师的编译环境是 GCC 9.3.0 和 Ubuntu 20.04 LTS。

然后，访问 https://127.0.0.1:8080 就能访问聊天界面了。

下一期你想看什么呢？是数据库，https，还是 websocket？欢迎在视频中投票表决。

点赞过 200，小彭老师火速更新下一期。
