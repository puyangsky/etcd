echo "building etcd..."
./build
echo "building done!"
sudo service etcd stop
sudo cp ./bin/* /opt/bin/
sudo service etcd start
rm -rf ~/k8slog/*
echo "done!"
