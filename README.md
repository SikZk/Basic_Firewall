To test project simply run:
```
cd tests
sudo chmod +x open_terminals.sh
sudo ./open_terminals.sh
```

Linting (clang-tidy):
```
cmake -S . -B build
cmake --build build
cmake --build build --target lint
```
