
echo "====================================================="
echo "  حمایت مالی از توسعه‌دهنده: TRON Wallet (TRC20)  "
echo "  TU4WSdCA51Kh1T67ryAUuP2uoYt7HevzkG                "
echo "====================================================="

if [ "$EUID" -ne 0 ]
  then echo "Please run as root."
  exit
fi
#echo nameserver 8.8.8.8 | sudo tee /etc/resolv.conf


if pgrep -x "RTT" > /dev/null; then
  echo "Tunnel is running!. you must stop the tunnel before update. (pkill RTT)"
  echo "update is canceled."
  exit
fi



apt-get update -y

REQUIRED_PKG="unzip"
PKG_OK=$(dpkg-query -W --showformat='${Status}\n' $REQUIRED_PKG|grep "install ok installed")
echo Checking for $REQUIRED_PKG: $PKG_OK
if [ "" = "$PKG_OK" ]; then
  echo "Setting up $REQUIRED_PKG."
  sudo apt-get --yes install $REQUIRED_PKG
fi

REQUIRED_PKG="wget"
PKG_OK=$(dpkg-query -W --showformat='${Status}\n' $REQUIRED_PKG|grep "install ok installed")
echo Checking for $REQUIRED_PKG: $PKG_OK
if [ "" = "$PKG_OK" ]; then
  echo "Setting up $REQUIRED_PKG."
  sudo apt-get --yes install $REQUIRED_PKG
fi

REQUIRED_PKG="lsof"
PKG_OK=$(dpkg-query -W --showformat='${Status}\n' $REQUIRED_PKG|grep "install ok installed")
echo Checking for $REQUIRED_PKG: $PKG_OK
if [ "" = "$PKG_OK" ]; then
  echo "Setting up $REQUIRED_PKG."
  sudo apt-get --yes install $REQUIRED_PKG
fi




printf  "\n"
printf  "\n"



echo "downloading RmnJL-SecureTunnel (اختصاصی)"

printf  "\n"

# نصب وابستگی results برای chronos
echo "Installing required Nimble packages (results)..."
nimble install -y results
if [ $? -ne 0 ]; then
  echo "[!] Nimble install results failed. Please check your Nim/Nimble installation."
  exit 1
fi
esac
wget  $URL -O v7.1_linux_amd64.zip

case $(uname -m) in
    x86_64)  URL="https://github.com/RmnJL/RmnJL-SecureTunnel/releases/latest/download/RmnJL_linux_amd64.zip" ;;
    arm)     URL="https://github.com/RmnJL/RmnJL-SecureTunnel/releases/latest/download/RmnJL_linux_arm64.zip" ;;
    aarch64) URL="https://github.com/RmnJL/RmnJL-SecureTunnel/releases/latest/download/RmnJL_linux_arm64.zip" ;;
    *)   echo "Unable to determine system architecture."; exit 1 ;;


wget  $URL -O RmnJL_linux.zip
unzip -o RmnJL_linux.zip
chmod +x RmnJL-SecureTunnel
rm RmnJL_linux.zip
echo "finished."

printf  "\n"