sudo service etcd stop
echo "building etcd..."
./build
echo "building done!"
sudo cp ./bin/* /opt/bin/
sudo service etcd start
rm -rf ~/k8slog/server.txt
rm -rf ~/k8slog/log.log
echo "done!"
