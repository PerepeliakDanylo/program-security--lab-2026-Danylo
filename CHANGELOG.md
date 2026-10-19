# Changelog

All notable changes to RDR2 Dynamic Reload (`DynamicReloadSpeed.asi`) are documented in this
file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Project documentation is kept in Ukrainian; this file, the shipped `README.txt`, the presets and
the plugin's log are in English.

## [1.0.0] - unreleased

First release of the runtime plugin. The offline `weapons.ymt` preprocessor that produced the
calibration values is versioned separately and is not part of this archive.

### Added

- Slow, deliberate reloads out of combat and stock-speed reloads in a gunfight, switched at
  runtime. Three fields are changed and no others: `AnimReloadRate`, `LoopRate`,
  `TimeBetweenBulletsInLoop`.
- Combat detection from independent signals, each with its own switch in `[Signals]` and its own
  tag in the log: player shooting, aiming, melee, recently damaged, hostile fighting the player
  nearby, law actively pursuing you, and Dead Eye. Aiming on its own never counts as combat - it is
  only counted together with "recently damaged" or "hostile nearby", so hunting a deer does not flip
  you into combat mode.
- The game build is read from the executable's own version resource, so the log always shows the
  same four numbers as the file's properties in Windows, and the reading keeps working after a game
  patch that no ScriptHook release knows about yet.
- Instant entry into combat mode, delayed exit through a separate cooldown state, so a second wave
  of enemies does not catch you in the slow profile. `CooldownSeconds` controls the delay; direct
  combat-to-calm is impossible by construction.
- Per-weapon values for the weapons listed in the shipped `.ini`. Out-of-combat values were solved
  from stopwatch measurements through the reload timing model; in-combat values are Rockstar's own
  stock values, read from an unmodified `weapons.ymt`.
- `Mode = auto`: per weapon, the plugin compares what the game loaded at startup against the stock
  reference table and decides which profile comes from the file and which from the snapshot, so the
  mod behaves correctly whether you run stock data or an already-slowed `weapons.ymt`. `Mode =
  manual` obeys the configuration literally, which is the recommended setting alongside a
  third-party weapon overhaul.
- Target discovery with no hard-coded addresses and no byte patterns: weapons are found by the hash
  of their own name, and the field offset is measured on the player's machine at every start, then
  accepted only if enough weapons independently agree on it. This is why a game update does not
  normally require a new build of the mod.
- An immutable snapshot of the three original values per weapon, taken once before the first write
  and restored when the mod is switched off, when the script unloads, on process detach, on any
  fatal path, and when a network session is detected.
- Three hotkeys: toggle the mod (restoring originals), force combat mode for testing, re-read the
  configuration without restarting the game. Re-reading the configuration never updates the
  snapshot.
- An optional on-screen state indicator, off by default.
- A file log with timestamps and `off / error / info / debug` levels, flushed after every line, with
  a size limit after which it stops writing instead of growing without bound. Every decision is
  logged with the numbers behind it.
- Tolerant configuration parsing: comments, missing keys, missing sections and non-numeric values do
  not stop startup; a built-in default is used instead and each substitution is logged.
- Three complete presets, shipped as `presets\subtle.ini`, `presets\realistic.ini` and
  `presets\hardcore.ini`, differing only in how slow the out-of-combat reload is. In-combat values
  are stock and identical in all three. None of them contains a `[Memory]` section.

### Fixed

- The CMake build now defines `WIN32_LEAN_AND_MEAN` and `NOMINMAX`, matching
  `DynamicReloadSpeed.vcxproj`, which already defined both. Without `NOMINMAX` the function-like
  `max(a,b)` macro from `<windows.h>` - included before `<algorithm>` in `Script.cpp` and
  `WeaponPatcher.cpp` - expands inside every `std::max(` call site and fails with C2589. Only the
  CMake path was affected, and that is the path `docs/BUILD.md` calls primary; the Visual Studio
  build stayed green, which is precisely what kept the defect hidden.
- The post-build packaging step copies `dist/presets/` into `package/`. It previously copied three
  items while `dist/README.txt` describes an archive of four including a `presets\` folder, so the
  documented release layout could not be reproduced by the documented build.
- `IgnoreVersionCheck` is now present in `[General]` of all three presets. It existed only in the
  main `.ini`, which left the presets structurally different from it for no stated reason.

### Security

- No network access, no telemetry, no data collection. The plugin writes one file, its own log, and
  reads one file, its own `.ini`.
- No configuration key can name an address or a base pointer. A manually forced field offset is
  restricted to the same search window as automatic discovery, and one outside that window is
  refused with a log line and no write.
- Every write is preceded by validation of the pointer and of the value currently at it, and by a
  comparison against the startup snapshot on the first write to a weapon. A mismatch - typically
  another mod writing the same fields - disables that one weapon loudly and leaves the rest working.
- Page protection is changed only around the write itself and always restored; every write is
  followed by a read-back that is logged with both numbers.
- The log contains file names without folders, so it cannot leak the Windows account name from a
  path. Attach it to bug reports freely.
- Oversized or absurd configuration files are rejected with a logged reason, and built-in defaults
  are used instead.
- An unrecognised game build is refused: the mod does nothing and the game is left exactly as it
  was. The refusal can be overridden in the configuration, which logs an error line naming the
  checks that still apply.
- If a network session is detected the plugin restores the original values and goes permanently
  idle. This is not a substitute for removing the file: before entering Red Dead Online, delete
  `DynamicReloadSpeed.asi`. The plugin disabling itself does not remove the module from the game
  process.

### Known limitations

- **Reload timing is global game data, so NPCs are affected too.** In combat, enemies reload at
  stock speed along with the player; out of combat they reload slowly along with the player. No
  per-character mechanism is known, and there is no workaround in this release.
- Single player only.
- `[Versions]` ships empty, which means "no build check configured": the mod works on a clean
  install without editing anything. Pinning it to one build is opt-in - copy the number from the
  log's `game build` line into `Supported`. It is not required to get started.
- The on-screen overlay is off by default and unverified. RDR2 has no GTA-style text commands; the
  drawing path used here exists on this build but its exact call order is not documented anywhere,
  so it may draw nothing. The state is always written to the log regardless.
- The Dead Eye signal ships switched off. The underlying check is confirmed to exist, but until it
  has been watched through a real session it stays off: a false positive would hold the mod in
  combat mode during quiet riding.
- Out-of-combat values for `WEAPON_REVOLVER_LEMAT`, `WEAPON_REVOLVER_NAVY`, `WEAPON_PISTOL_M1899`,
  `WEAPON_REPEATER_EVANS` and `WEAPON_RIFLE_ELEPHANT` are estimates, not measurements, and their
  in-combat values assume an engine default. These five have no entry in the game's weapon data
  file at all, so they could not be measured before now. A stopwatch measurement turns them into
  real numbers.
- The "wanted by law" signal is implemented and ships **on** (`WantedByLaw = 1`): the underlying
  check was confirmed against the native database on 2026-09-28. The "Dead Eye" signal is equally
  implemented but ships **off** (`DeadEye = 0`) for the reason given two entries above — it is a
  default, not a missing feature, and flipping the key to `1` enables it without a rebuild.
- If the plugin cannot confirm where the reload fields are, it does nothing and says so in the log.
  On an unlucky game update that is the expected outcome rather than a crash.
- If the layout of the four weapon-condition blocks cannot be determined, only the clean-weapon
  block is patched (`conditions: good only (stride unresolved)`) and the clean/worn difference stays
  as the game shipped it.
- Frame-rate impact and memory growth have not been measured yet. The measurement method is defined
  in the project test plan; no figure is claimed until it has been run.

<!-- No link reference for [1.0.0]: the release is not tagged yet. Add the tag comparison link
     when v1.0.0 is tagged in the repository. -->
