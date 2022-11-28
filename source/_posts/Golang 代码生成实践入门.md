---
title: 如何实现一个 Golang 代码生成器
date: 2022-11-27 18:00:00
---

> A property of universal computation—Turing completeness—is that a computer program can write a computer program. This is a powerful idea that is not appreciated as often as it might be, even though it happens frequently. -- Rob Pike *[Generating Code](https://go.dev/blog/generate)*

代码生成是编译器很大的一部份。举例来说，`go test` 命令就依赖于代码生成来执行测试，首先扫描被测试的包，然后生成一个 Go 应用，包含被测试包及相关脚手架代码，其可以被 `go` 命令编译运行并输出相应的测试报告。依靠现代计算机强大的性能，看起来复杂的代码生成一般只需要耗费几秒钟的时间。

代码生成一般用来辅助开发者生成一些结构类似，重复度高的，但又依赖于程序的其它部份的代码。如：Java 中的 Lombok 可以用注解的方式在编译时给类添加 `getters/setters` 函数，Golang 中的 `stringer` 可以为枚举类型生成对应的 `String()` 方法等等，类似的代码生成的应用场景非常广泛，更有依赖 AI 来更智能地生成代码的 **Github Copilot**。

一方面，人工编写 `getters/setters` 或 `stringer` 这类代码只是繁复的体力活，非常无趣；另一方面，这类代码会随着字段变更，枚举类型增加而频繁更新，容易遗漏。因此，交给代码生成器来做这类工作再合适不过了。 Golang 官方和社区提供了诸如 `stringer`, `mockgen` 等代码生成工具；但在实践中，我们极有可能需要根据自己的场景来生成代码，了解如何设计实现一个代码生成器就非常有必要了。

本文通过实际项目中应用到的例子，来探讨一下如何利用 Golang 提供的包，命令等来实现我们需要的代码生成器。

## **如何生成测试代码**

Golang 社区有 **[cweill/gotests](https://github.com/cweill/gotests)** 可以生成函数或者方法的单元测试脚手架代码，开发者只需要填充测试用例，稍微修改一下结构定义或校验的代码就可以快速写出高质量的单测了。

### **场景**

然而，我们的例子中，需要更进一步，扫描一个包及其子包下面定义的所有导出的同一种类型的变量，并执行变量上的一个方法来检查变量定义的正确性。简化的代码如下：

``` go
// file schema.go
// Schema 定义校验一个数据结构的规则集。
// 如：用户注册表单中用户名必须是字母开头，没有特殊符号等等。
type Schema struct {
    Validators []string
}

// Check 检查 Schema 中的 Validator 配置是否正确。
// 如：定义了一个字段必须小最长度是 10, 最大长度是 5，这种配因为任意数据检查都会失败，显然是不合理的。
func (s *Schema) Check() error {
    /* ... some checks */
    return errors.New("validator xxx invalid")
}

// 业务代码
// file register.go
var RegisterForm = &Schema{/* ... */}

// file login.go
var LoginForm = &Schema{/* ... */}

// 我们需要的测试代码
// file schemas_test.go
func TestingForms(t *testing.T) {
    for i, f := range []*Schema{ RegisterForm, LoginForm } {
        t.Run("check form " + strconv.Itoa(i), func(t *testing.T) {
            if err := f.Check(); err != nil {
                t.Error(err)
            }
        })
    }
}
```

针对上面这个场景，手写每个 Schema 变量对应的单测代码，纯粹的体力活，还容易遗漏；另一方面，如果将 `Check()` 逻辑的执行推迟到业务程序运行时则为时已完，发现问题需要经过代码修改，测试，部署一系列操作来修复。此时，用代码生成器来自动扫描类型为 `*Schema` 的导出变量并生成相应的 `_test.go` 单元测试文件，将 Schema 检查集成到开发或 CI/CD 环节就十分合理了。接入下介绍一些需要用来的工具。

### **//go:generate 注释**

用过 `stringer` 或 `mockgen` 的同学肯定知道，可以在源代码中写 `//go:generate` 注释，配合在命令行中执行 `go generate` 命令就可以触发代码生成。如：`//go:generate stringer -type=Pill` 可以用来生成枚举类型的 `String()` 方法。注释中的 `stringer` 是一个在 `$PATH` 中存在的可执行程序，后面的 `-type=Pill` 是程序的入参。当在源代码所在的目录下执行 `go generate .` 命令时，`go` 会扫描当前目录源码中的 `//go:generate` 注释并逐个执行其中的命令，以此来执行 `stringer` 程生成代码。

### **源代码扫描**

触发了可执行程序后，就需要在程序中扫描源代码，构造 AST；理论上这个程序可以是任何可执行程序或者脚本，只要它能正确解析我们写的 Golang 源代码，让我们找到定义的 `*Schema` 类型的变量就够了。实际上，Golang 1.5 开始就实现了自举，官方也提供了 [`golang.org/x/tools/go/packages`](https://pkg.go.dev/golang.org/x/tools@v0.1.12/go/packages) 这个工具包，可以用来加载 Golang 源代码，构造 AST.

### **text/template**

扫描完代码，我们就需要根据定义的 `*Schema` 来生成对应的测试代码，在生成的目标代码中，大部分代码是固定的，只有变量定义和变量导入的部分是变化的。因此，我们可以利用 [`text/template`](https://pkg.go.dev/text/template) 文本模板，将变化的部份定义为占位符，在执行模板时传入变量替换占位符生成最终的单元测试代码。

### 示例代码

利用前面提到的工具，我们基本上就可以写一个 `main.go` 程序来实现测试代码的生成了，以前文的**场景**为例。

``` go
// file main.go
package checker

import (
    // 其它标准包的导入忽略
    "text/template"
    "golang.org/x/tools/go/packages"

    // for embedding template file
    _ "embed"
)

var _template *template.Template

//go:embed checker_test.go.template
var templateFile embed.FS

func init() {
    template, _ := template.ParseFS(templateFile, "checker_test.go.template")
    _template = template
}

func main() {
    formattedSource, err := loadPackageAndGenerateSource()
    if err != nil {
        return log.Fatal(err)
    }
    // 将测试代码写到文件或输出到控制台
}

func loadPackageAndGenerateSource() ([]byte, error) {
    cfg := &packages.Config{ Mode: packages.NeedName | packages.NeedTypes | packages.NeedTypesInfo, }
    // 扫描 "./..." 当前目录和所有子目录下面的包
    schemaPackages, _ := packages.Load(cfg, "./...")
    schemas := findAllExportedSchemas(schemaPackages)
    var sourceBuffer bytes.Buffer
    // 执行模板生成代码
    _ = _template.Execute(&sourceBuffer, schemas); err != nil {
    // 格式化生成的代码
    return format.Source(sourceBuffer.Bytes())
}

func findAllExportedSchemas(packages []*packages.Package) []string {
    var schemas []string
    for _, pkg := range packages {
        scope := pkg.Types.Scope()
        for _, name := range scope.Names() {
            object := scope.Lookup(name)
            // types.Object 可以是包中声明的 struct, interface, var 等等
            if !object.Exported() {
                continue
            }
            // 通过 object.Type().String() 和 reflect.TypeOf(*Schema(nil)) 判断
            // object 是否为 *Schema 类型变量
            schemas = append(schemas, object.Name())
        }
    }
    return schemas
}

// 代码模板文件 checker_test.go.template
// 其中用 {{}} 来定义占位符，用 {{range}}{{end}} 来迭代，参考：https://pkg.go.dev/text/template
// _template.Execute(&sourceBuffer, schemas) 中的第二个参数 schema 变量名数组
func TestSchemas(t *testing.T) {
    for i, f := range []*Schema{ {{range $schemaVariable := .}}{{$schemaVariable}},{{end}} } {
        t.Run("check schema {{$schemaVariable}}", func(t *testing.T) {
            if err := f.Check(); err != nil {
                t.Error(err)
            }
        })
    }
}
```

**关于示例代码**：

- 上面的例子做了非常多的简化，包括错误检查，生成的代码中引用 Schema 变量对应的导入，生成代码输出到文件中等等
- 采用了 `embed` 包来加载代码模板（文本文件），这在代码模板比较长和复杂时有用，特别是代码中有 `back quote` 符号不适合放在  Raw String 中
- `golang.org/x/tools/go/packages.Load()` 加载代码是以包为单位的，而不是文件，Golang 中一个包可以拆成多个文件，Schema 变量定义也可以分散在不同文件
- 包的加载会忽略 `.`, `_` 开头的文件和 `testdata` 目录，这与其它 `go tool` 是一致的，详细的解释可以在 `go help packages` 命令中查看

## **代码生成工具的发布和使用**

我们用 Golang 编写的代码生成工具，本质上是一个可执行程序，最终会交付给开发者使用。开发者通过 `//go:generate` 注释配合 `go generate` 命令即可在开发阶段生成代码，也可以方便地集成到 CI/CD 环节。

### **可执行文件方式**

假设上文实现的工具为 gitwhatever.com/tools/cmd/checker，则用户需要用 `go install gitwhatever.com/tools/cmd/checker` 命令将 `checker` 可执行文件安装到 $GOPATH/bin 目录下，确保 `go generate` 命令可以通过 $PATH 找到 `checker` 并执行代码生成。对于 `//go:generate checker` 注释，`checker` 执行时的当前目录就是源代码所在的目录，因此 `packages.Load("./...")` 就会加载源代码目录及其所有子目录的包。而如果直接在命令行运行 `checker` 命令的话，就需要先切换当前目录了。

### **go run 方式**

可执行文件的方式依赖于用户主动安装和更新工具到最新版本。前面提到 `//go:generate ${cmd}` 注释的作用只是告诉 `go generate` 执行 `${cmd}` 命令，这个命令可以是 `checker`，当然也可以是 go run gitwhatever.com/tools/cmd/checker，因此注释为 `//go:generate go run gitwhatever.com/tools/cmd/checker` 可以一举解决需要安装和更新命令的问题，特别是当代码生成工具是跟依赖的代码(`Schema`定义)一起发布时，可以确保版本是兼容的。

## **代码静态信息和动态信息**

利用 `golang.org/x/tools/go/packages` 这样的工具，我们可以方便地加载分析源代码，构建 AST，获取我们需要的源代码中所有的静态信息，如包名，变量名，函数名，甚到注释信息等；但对于代码运行时的动态信息，这类工具就无能为力了。为什么会用到代码运行时的信息呢？举一个实践中遇到的场景：

``` go
type Schema struct {
    Unions     []*Schema
    Validators []string
}

// foo.go
var Foo = &Schema {
    Unions: []*Schema{
        bar.Bar, 
        func() *Schema { 
            if someCondition {
                return fuzz.Fuzz
            }
            return whateverSchema
        }(),
    }
    Validators: []string{/*...*/}
}

// bar.go
var Bar = &Schema {
    Validators: []string{/*...*/}
}

// fuzz.go
var Fuzz = &Schema {
    Validators: []string{/*...*/}
}
```

对于上面的 Schema `Foo` 其不仅包含了自己的 Validators 还包含了动态地从 `Bar`, `Fuzz` 合并过来的 Validators，对于 `Bar` 这个简单的变量引用，可能可以通过递归的处理来解决，但是对于 `Fuzz` 的引用，是通过运行一段逻辑来返回的，要想通过静态的代码分析来获取 `Foo` 完整的 Validator 中比较困难了。

然而，如果将 `Foo` 加载到运行时，那 `Foo` 的定义自然而然就得到了。这个场景就描述了，我们在代码生成时，可能既需要代码的静态信息和代码运行时的动态信息。

### 解决思路

这种既要又要的场景，我们需要在生成的代码的思路上做一点改变。

``` plaintext
原来的方式：
foo.go/bar.go/fuzz.go -> generator(eg: checker) -> generated_code.go

改变后的方式：
foo.go/bar.go/fuzz.go -> generator(eg: checker) -> (intermediate generator)temp/main.go ->  generated_code.go
```

可以看到，改变后的方式，在生成器 `generator` 和目标代码 `generated_code.go` 之间增加了一个中间的生成器 `intermediate generator`，实际上也是一个可以通过 `go run temp/main.go` 执行的程序，这个改变使我们有机会在其中导入 `Foo` 变量，获取其运行时的信息，再加上前面的 `generator` 将静态信息通过模板替换等方式注入到 `temp/main.go` 就可以实现了。再通过一些后置的步骤清理掉中间的生成器代码即可，具体代码就不再赘述。

至此，我们对于如何在 Golang 中实现一个代码生器做了简单的探讨，如有错漏，祈为指正 ^_^

参考文档：

- [Generating code](https://go.dev/blog/generate)
- [A comprehensive guide to go generate](https://eli.thegreenplace.net/2021/a-comprehensive-guide-to-go-generate/)
