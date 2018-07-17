# r2angr

Use angr inside the radare2 debugger.

Create an angr state from the current debugger state.

## Install

`pip install r2angr`

## Usage

r2angr implements the [angrdbg](https://github.com/andreafioraldi/angrdbg) API, you can use it after the call to `r2angr.init`

```python
import r2pipe
import r2angr

r2 = r2pipe.open("stuff")
r2angr.init(r2)

r2.cmd("l33t r2 cmd")

sm = r2angr.StateManager()
# stuffs with angrdbg StateManager ...
```

see the [examples](https://github.com/andreafioraldi/r2angr/tree/master/examples) folder.
