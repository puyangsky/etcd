sudo service etcd stop
rm -rf ~/k8slog/server.txt
rm -rf ~/k8slog/log*
echo "building etcd..."
./build
echo "building done!"
sudo cp ./bin/* /opt/bin/
sudo service etcd start
echo "done!"
