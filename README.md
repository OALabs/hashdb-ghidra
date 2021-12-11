# hashdb-ghidra

This is a Ghidra plugin for [HashDB][]. It allows you to compile a list of API hashes and then to
query the HashDB web service for possible matching strings. It collects these associations into an
enum or a struct. From there on, you are on your own.

## Installation

Two options:

1. Copy `HashDB.java` to your `ghidra_script` directory.
2. Add the location where `HashDB.java` is located to your script directory search path in Ghidra's
   ScriptManager.

We recommend to bind the `HashDB.java` script's execution to a hotkey, preferably <kbd>F3</kbd>.

## Usage

The plugin consists of a single window containing a table showing the "currently collected" hashes.
You can bring up the window by executing the script (i.e. hitting <kbd>F3</kbd>). In addition to
opening the window (or showing it, if it was hidden) the script will do different things depending
on where your cursor is:

* If the cursor is on an immediate or constant, it will add that value as a hash to the table.
* If you selected a memory region, it will interpret it as a list of hashes.
* Otherwise, it will assume that you want to scan for parameters to the currently opened function.

The GUI is actually perfect and completely intuitive to use with a great UX. But since we are also
amazing at documentation, we include the following guidance:

* The plugin allows to transform the hash before lookup. You can put a JavaScript expression into
  the "Hash Transformation" input field. See the REvil example below.
* When you hit the "Query!" button, the script will use the HashDB web API to list all known and
  matching hashing algorithms. If there's only one, it will also just resolve all hashes. Otherwise,
  you have to select the correct algorithm in the "Hash Algorithm" field. Pretty much the same is
  true for the "String Permutation" field.
  **tl;dr:** just click "Query!".
* You can check the "Resolve Entire module" checkbox if you not only want to add all hashes from the
  table but also all other hashes from the parent DLLs.
* The "Scan Function" tab allows you to specify a function name and a parameter location. The script
  will crawl all function calls and add the corresponding argument to the table.
* Depending on the different switches and toggles in the "Output"-tab (which is very well-designed),
  the script will create one or two enums or structs. The order of fields in the resulting structs
  is the same as in the table. Structs are always overwritten, enums are always merged.

## Example Workflow: Netwalker

Consider the sample with the following SHA256 hash
```
de04d2402154f676f757cf1380671f396f3fc9f7dbb683d9461edd2718c4e09d
```
and navigate to the function at `0x00401360`. The code will look like the following:
```c
iVar1 = FUN_00401220(0x84c05e40);
if (iVar1 != 0) {
  pcVar2 = (code *)FUN_00401000(iVar1,-0x5e2ba68c);
  if (pcVar2 != (code *)0x0) {
    uVar6 = 0x254;
    uVar5 = 8;
    uVar3 = FUN_00406a40();
    DAT_00417194 = (int *)(*pcVar2)(uVar3,uVar5,uVar6);
    if (DAT_00417194 != (int *)0x0) {
      iVar4 = FUN_00401000(iVar1,-0x5e2ba68c);
      *DAT_00417194 = iVar4;
      iVar4 = FUN_00401000(iVar1,-0x50ee43dc);
      DAT_00417194[1] = iVar4;
      iVar4 = FUN_00401000(iVar1,-0x468c4724);
      DAT_00417194[2] = iVar4;
      iVar4 = FUN_00401000(iVar1,-0x7b9c69f6);
/* ... */
```
You can either click on `0x84C05E40`, hit <kbd>F3</kbd>; click on `-0x5E2BA68C`, hit <kbd>F3</kbd>,
and so on and so forth, until you are ready to "Query!". Alternatively you can double click
`FUN_00401000` and _then_ hit <kbd>F3</kbd> to bring up the scan function tab. Confirm that the
pre-populated value in the "Parameter" field is correct, hit "Scan" and grab a cold cup of water.

## Example Workflow: REvil

Consider the sample with the following SHA256 hash
```
5f56d5748940e4039053f85978074bde16d64bd5ba97f6f0026ba8172cb29e93
```
and navigate to the memory region `0x004113F8` and convert it to an array of 140 DWORDs and hit
<kbd>F3</kbd>. This memory region contains all API hashes. Our goal is to create a struct that has
the corresponding API function pointers in the exact same location. This way, changing the type of
this global constant to the struct will make the code all pretty.

REvil's API hashing requires that you figure out a transformation that it applies to the hash. For
this sample, the transformation is the following:
```
((((X ^ 0x76C7) << 0x10) ^ X) ^ 0xAFB9) & 0x1FFFFF /*REvil*/
```
It will be different for other REvil samples. Make sure to select "Generate Struct" in the "Output"
tab and "Query!". When it is done, change the type of `0x004113F8` to `HashDB`. Happy times.

## Contributors

Contact us on Twitter

* Jesko Hüttenhain [@huettenhain][]
* Lars Wallenborn [@larsborn][]

or join the [OALabs][] Discord [oalabs-dev][] channel.

[oalabs-dev]: https://discord.gg/cw4U3WHvpn
[HashDB]: https://github.com/OALabs/hashdb
[OALabs]: https://oalabs.openanalysis.net/
[@huettenhain]: https://twitter.com/huettenhain
[@larsborn]: https://twitter.com/huettenhain
