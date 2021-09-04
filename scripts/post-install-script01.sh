#https://www.digitalocean.com/community/tutorials/how-to-install-and-secure-redis-on-ubuntu-20-04

sudo apt update

sudo apt-get install redis-server

sudo apt-get install make pkg-config libssl-dev

wget https://download.redis.io/releases/redis-6.2.5.tar.gz
tar xzf redis-6.2.5.tar.gz
cd redis-6.2.5
make distclean

make distclean

make BUILD_TLS=yes MALLOC=libc

./utils/gen-test-certs.sh

sudo apt-get install -y tcl-tls

#./runtest --tls

cd utils

cd create-cluster

. create-cluster start

. create-cluster create

#enable the firewall
sudo ufw allow 6379

#create some users
redis-cli ACL SETUSER chris on allkeys +set >S2@dmins2@dmin
redis-cli ACL SETUSER john on allkeys +set >S2@dmins2@dmin
redis-cli ACL SETUSER mary on allkeys +set >S2@dmins2@dmin

#manual cluster setup...
#setup bind to all IPs
sudo sed -i 's/bind 127.0.0.1/bind 0.0.0.0/' /etc/redis/redis.conf

#setup cluster
sudo sed -i 's/# cluster-enabled yes/cluser-enabled yes/' /etc/redis/redis.conf

sudo sed -i 's/# cluster-config-file nodes-6379.conf/cluster-config-file nodes.conf/' /etc/redis/redis.conf

sudo sed -i 's/# cluster-node-timeout 5000/cluster-node-timeout 5000/' /etc/redis/redis.conf

#create the node directrories
mkdir cluster-test
cd cluster-test
mkdir 7000 7001 7002 7003 7004 7005

#create the cluster
redis-cli --cluster create 127.0.0.1:7000 127.0.0.1:7001 \
127.0.0.1:7002 127.0.0.1:7003 127.0.0.1:7004 127.0.0.1:7005 \
--cluster-replicas 1

#push one of all types...

#simple string


#redis list
rpush mylist A
rpush mylist B
rpush mylist first

#hash
hmset user:1000 username antirez birthyear 1977 verified 1

#redis set
sadd myset 1 2 3

#sorted sets
zadd hackers 1940 "Alan Kay"
zadd hackers 1957 "Sophie Wilson"
zadd hackers 1953 "Richard Stallman"
zadd hackers 1949 "Anita Borg"
zadd hackers 1965 "Yukihiro Matsumoto"
zadd hackers 1914 "Hedy Lamarr"
zadd hackers 1916 "Claude Shannon"
zadd hackers 1969 "Linus Torvalds"
zadd hackers 1912 "Alan Turing"