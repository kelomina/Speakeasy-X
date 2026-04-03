# 安装

Speakeasy 需要 Python 3.10+。

## 从 PyPI 安装

```console
python3 -m pip install speakeasy-emulator
```

可选的 GDB 支持：

```console
python3 -m pip install "speakeasy-emulator[gdb]"
```

验证安装：

```console
speakeasy -h
```

## 从源代码安装

```console
git clone https://github.com/mandiant/speakeasy.git
cd speakeasy
python3 -m pip install -e ".[dev]"
```

从源代码安装可选的 GDB 支持：

```console
python3 -m pip install -e ".[dev,gdb]"
```

## 相关文档

- [项目 README](../README.md)
- [文档索引](index.md)
- [命令行参考](cli-reference.md)
- [帮助和故障排除](help.md)
