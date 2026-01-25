#!/bin/bash
set -e
sudo apt install -y dbus-x11


echo "Building and starting containers in detached mode..."
sudo docker compose up -d --build

echo "Waiting for containers to be ready..."
sleep 5

open_terminal() {
    local container_name=$1
    local cmd="docker exec -it $container_name /bin/bash"

    if command -v gnome-terminal &> /dev/null; then
        gnome-terminal --title="$container_name" -- bash -c "$cmd"
    elif command -v xfce4-terminal &> /dev/null; then
        xfce4-terminal --title="$container_name" -e "$cmd" &
    elif command -v konsole &> /dev/null; then
        konsole -e "$cmd" &
    elif command -v xterm &> /dev/null; then
        xterm -title "$container_name" -e "$cmd" &
    else
        echo "Warning: No supported terminal emulator found (gnome-terminal, xfce4-terminal, konsole, xterm)."
        echo "Please manually run: $cmd"
    fi
}

echo "Opening terminal for host1..."
open_terminal "host1"

echo "Opening terminal for host2..."
open_terminal "host2"

echo "Opening terminal for firewall..."
open_terminal "firewall"

echo "Terminals launched."

sudo docker compose logs -f firewall