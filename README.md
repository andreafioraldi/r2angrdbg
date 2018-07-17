# r2angrdbg

Use angr inside the radare2 debugger.

Create an angr state from the current debugger state.

## Install

`pip install r2angrdbg`

## Usage

r2angr implements the [angrdbg](https://github.com/andreafioraldi/angrdbg) API, you can use it after the call to `r2angrdbg.init`

```python
import r2pipe
import r2angrdbg

r2 = r2pipe.open("stuff")
r2angrdbg.init(r2)

r2.cmd("l33t r2 cmd")

sm = r2angrdbg.StateManager()
# stuffs with angrdbg StateManager ...
```

see the [examples](https://github.com/andreafioraldi/r2angrdbg/tree/master/examples) folder.
