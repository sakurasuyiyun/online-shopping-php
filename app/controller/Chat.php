<?php
declare(strict_types=1);

namespace app\controller;

use Ratchet\MessageComponentInterface;
use Ratchet\ConnectionInterface;
use think\Log;

// use Ratchet\RatchetMessageComponentInterface;
// use Ratchet\RatchetConnectionInterface;
// use Ratchet\RatchetServerIoServer;
// use Ratchet\RatchetHttpHttpServer;
// use Ratchet\RatchetWebSocketWsServer;


class Chat implements MessageComponentInterface
{
    protected $clients;
    protected $pdo;
    protected $redis;

    public function __construct()
    {
        $this->clients = new \SplObjectStorage;

        Log::info('has connet');

        // 连接到数据库
        $dsn = 'mysql:host=localhost;dbname=chat';
        $username = 'root';
        $password = 'root';
        $options = [
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
            \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC
        ];
        $this->pdo = new \PDO($dsn, $username, $password, $options);

        // 连接到 Redis
        $this->redis = new \Redis();
        $this->redis->connect('localhost', 6379);
    }

    public function onOpen(ConnectionInterface $conn)
    {
        // 连接建立时等待接收用户标识信息
        // $conn->userId = null; // 初始化用户标识

        // $data = json_decode($msg, true);
        // $conn->userId = $data['data']; // 保存用户标识

        $this->clients->attach($conn);
        echo "New connection ({$conn->resourceId})\n";

    }

    protected function getClientByUserId($user_id)
    {
        foreach ($this->clients as $client) {
            if ($client->user_id === $user_id) {
                return $client;
            }
        }
        return null;
    }

    public function onMessage(ConnectionInterface $from, $msg)
    {
        echo "有消息进来了" . $msg;

        $isFirst = 0;

        $data = json_decode($msg, true);
        $data['created_at'] = date("Y-m-d H:i:s");

        if (isset($data['isFirst']) && !empty($data['isFirst'])) {
            $isFirst = 1;
            foreach ($this->clients as $client) {
                if ($client == $from) {
                    $client->user_id = $data['data'];
                }
            }
        }

        foreach ($this->clients as $client) {
            // if ($client !== $from) {
            //     $client->send($msg);
            // }
            if (isset($data['to']) && !empty($data['to'])) {
                $targetClient = $this->getClientByUserId($data['to']);
                if ($targetClient) {
                    $targetClient->send($data['message']);
                }
            }
        }

        $msg = json_encode($msg);
        // 将消息存入 Redis
        if ($isFirst == 0) {
            $this->redis->rpush('messages', $msg);
        }

        // 如果 Redis 中的消息数量超过 1000，则将消息存入数据库
        if ($this->redis->llen('messages') > 1) {
            $messages = $this->redis->lrange('messages', 0, -1);

            // 开始事务
            $this->pdo->beginTransaction();

            foreach ($messages as $message) {
                $message = json_decode($message, true);

                // 将消息存入数据库
                $stmt = $this->pdo->prepare('INSERT INTO messages (`from`, `message`, `to`, `created_at`) VALUES (?, ?, ?, ?)');
                $stmt->execute([$message['from'], $message['message'], $message['to'], date("Y-m-d H:i:s")]);

                // 从 Redis 中删除已经存入数据库的消息
                $this->redis->lpop('messages');
            }

            // 提交事务
            $this->pdo->commit();
        }
    }

    public function onClose(ConnectionInterface $conn)
    {
        $this->clients->detach($conn);
        echo "Connection {$conn->resourceId} has disconnected\n";
    }

    public function onError(ConnectionInterface $conn, \Exception $e)
    {
        echo "An error has occurred: {$e->getMessage()}\n";
        $conn->close();
    }

    public function joinGroup(ConnectionInterface $conn, $groupId)
    {
        // 将用户加入群组
        $this->groups[$groupId][] = $conn;
        echo "User ({$conn->resourceId}) joined group {$groupId}
    ";
    }

    public function leaveGroup(ConnectionInterface $conn, $groupId)
    {
        // 将用户从群组中移除
        $index = array_search($conn, $this->groups[$groupId]);
        if ($index !== false) {
            unset($this->groups[$groupId][$index]);
            echo "User ({$conn->resourceId}) left group {$groupId}
    ";
        }
    }

    public function subscribe(ConnectionInterface $conn, $topic)
    {
        // 订阅某个主题
        $conn->topics[] = $topic;
        echo "User ({$conn->resourceId}) subscribed to {$topic}
    ";
    }

    public function unsubscribe(ConnectionInterface $conn, $topic)
    {
        // 取消订阅某个主题
        $index = array_search($topic, $conn->topics);
        if ($index !== false) {
            unset($conn->topics[$index]);
            echo "User ({$conn->resourceId}) unsubscribed from {$topic}
    ";
        }
    }

}