# 一段简短的脚本代码 Lint PATH 变量

在不同开发环境不同账户下，需要往 PATH 变量中加入不同的文件夹，同时为了集中管理，
通常我会把 `.bashrc`, `.zshrc` 等 dotfiles 放到 Github 上，这就导致一个 rc 文件
需要适配 MacOS, Linux 环境；不同环境需要加的文件夹可能不一样，一开始我的方法是
按主机名，后来是写一个 append_path 函数，在加文件夹时检查参数是否为存在，是否为
文件夹，是否已经加过。

去重的必要性，添加文件夹到 PATH 时，一般用的是增量的 PATH=$PATH:/path/to/dir ,
同时修改 rc 后我通常是用 source 命令来使修改生效，这样每 source 一次就会使 PATH
附上同一个文件夹，对于有洁癖的我来说无法接受。

最新的解决方法是，附加文件夹到 PATH 时不做任何处理，只在 rc 脚本的最后 lint 一下
PATH 变量，确保 PATH 中的文件夹是存在的且不重复的。

```sh
# Lint PATH: remove directory not exists, remove duplicates
# Use colon as delimiter, append a colon to $PATH to read the last path dir
declare new_path=""
while read -r -d : dir; do
  if [[ -n "$dir" && -d "$dir" && ":$new_path:" != *:"$dir":* ]]; then
    new_path+="$dir":
  fi
done <<<"$PATH":
PATH=${new_path%:}
unset new_path
export PATH
```
