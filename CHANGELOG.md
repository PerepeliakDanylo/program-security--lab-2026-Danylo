# Changelog

All notable changes to RDR2 Dynamic Reload (`DynamicReloadSpeed.asi`) are documented in this
file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Project documentation is kept in Ukrainian; this file, the shipped `README.txt`, the presets and
the plugin's log are in English.

## [1.2.1] - unreleased

Polish after the 1.2.0 test (two in-game logs on 2026-10-27, build 1.0.1491.50: the first on an
overhauled, slowed `weapons.ymt`, the second on a `weapons.ymt` with stock reload values). 1.2.0
passed: every weapon bound by class (59 of 59 names, 0 unbound), every switch under 0.1 ms, the
stopwatch matched the model (LeMat 16.1 s calm / 7.9 s combat, Navy 9.4 / 6.1, M1899 3.5 / 2.1).
The logs and the developer's notes showed four small things, fixed here; a review of the
requirements against the code found a fifth (restore had no read-back). No INI key was added or
renamed; an INI from 1.2.0 works unchanged.

### Fixed

- **The state no longer flickers between COMBAT and COOLDOWN while you shoot.** 1.2.0 counted a
  shot for one detector poll (a quarter of a second), so with shots further apart than that the
  state went to COOLDOWN between two shots and back to COMBAT on the next one - in the overlay
  and as two log lines per shot. Reload speed was not affected (the cooldown keeps the combat
  values), but the readout jumped. A shot now counts for two seconds, for `PlayerShooting` and
  for `ShootingSustainsCombat` alike; the cooldown starts two seconds after the last shot.
- **Switching the mod off ends a fight forced with F8.** In 1.2.0 the forced fight outlived the
  pause, so switching the mod back on went straight from CALM to COMBAT - against the documented
  "back on: always calm".
- **Only hand-held firearms are adopted as unlisted guns.** The game's "gun" flag is also set on
  the vehicle-damage pseudo-weapons `WEAPON_RAMMED_BY_CAR` and `WEAPON_RUN_OVER_BY_CAR`, and 1.2.0
  adopted both. They are never reloaded, so nothing changed in play, but a weapon now also has to
  be a revolver, pistol, repeater, rifle, shotgun or sniper rifle by the game's own class.
- A weapon label that is the internal name itself (`WEAPON_…`, seen for those two) is checked
  against the hash too, so the log says `name verified` when it is.
- **Restoring the original values reads each one back**, like every write already did: F7, unload
  and every error path now confirm the snapshot actually landed, and log an error if it did not.
  At `debug` level each restored field gets one line - `restored: <weapon> X -> Y (boot
  snapshot), read back Y` - which is the per-weapon comparison the project's requirement for
  switching off (FR-28) asks the log to show; 1.2.0 logged only the total.

### Added

- **Dual wielding on the overlay.** Two identical revolvers or pistols drawn: one line ending in
  `x2`. Two different ones: the right-hand gun on the second line, the left-hand gun on a third
  line, each with its own reload rate. A long gun carried lowered in the left hand is still not
  shown (it cannot fire). The log gets a `weapon in left hand: …` line the first time each gun is
  drawn in the left hand.

### Changed

- `README.txt` and the INI comment on `HotkeyToggleMod` say what "original values" means: the
  values the game loaded at start-up from the installed `weapons.ymt` - stock with a stock file,
  slower with an overhaul or a hand-slowed file. Observed in both 1.2.0 runs and correct by design.
- Log: `unlisted: … of them hand-held guns …, … not hand-held guns …` (was `guns` / `not guns`).

## [1.2.0] - unreleased

Second update after play-testing, driven by two in-game logs of the 1.1.0 test build (one at
`info`, one at `debug` level) on build 1.0.1491.50 and by the developer's notes from that session.
1.1.0 was never released; its changes are listed below as they were, and 1.2.0 supersedes the
parts of it that the logs proved wrong.

### Fixed

- **No more freeze on every switch between calm and combat.** 1.1.0 asked the operating system
  twice per weapon field whether the page was usable and writable. On this game one such query
  into the multi-gigabyte heap that holds the weapon data takes about 4 ms, so every switch froze
  the game for 400-600 ms (the log measured it on every transition, at `info` level too). Since
  1.2.0 the plugin makes no system call at all on that path: addresses are validated once, when the
  weapons are found, against the memory map the scan already built; each write is guarded by
  in-process checks only. A switch now takes tens of microseconds for all weapons. The same fix
  removes the hitch right after the start-up scan (the first calm write) and 0.3 s of start-up time.
- **The Cattleman and Double-Action revolvers switch again**, and every other weapon is tied to the
  right structure. A weapon's name occurs thousands of times in memory - every ped's loadout,
  every inventory - and 1.1.0 kept only the first 64 occurrences per name: the base Cattleman's real
  weapon data lay behind them on both logged launches, so it was never switched, and the base
  Double-Action was once tied to an unrelated structure. 1.2.0 keeps 4096 occurrences per name and,
  more importantly, recognises the weapon data by its structure: it learns from the data which
  pointer into the game executable sits at a fixed distance from the name in every confirmed weapon
  structure (the class's vtable) and only accepts objects that carry it. A second pass enumerates
  every object of that class, so a structure lying behind even more mentions is still found.
- **The LeMat, Navy, M1899, Evans and Elephant Rifle no longer work "on some launches only".**
  1.1.0 tied weapons without a known reference value to the first structure with a plausible
  number - a different structure on different launches (the logs show the Navy at 1.0 once and at
  3.0094 the next time). Nothing is bound by plausibility any more: by structure, or by an exact
  known value, or not at all.
- **A shot at a person is a fight.** With `PlayerShooting = 0` (calm while hunting) 1.1.0 stayed calm
  even when you shot a person. 1.2.0 checks the target of every shot - the entity under the
  crosshair or locked on to - and a living person, or one the shot just killed, starts combat
  (`AttackingHumans`, on by default). Animals never count.
- **Shots keep a fight going.** In 1.1.0 a shove started combat, the cooldown began a second later and
  shooting during it did not bring combat back. Now any shot of yours during combat or cooldown
  keeps the fight on (`ShootingSustainsCombat`, on by default); in calm it still starts nothing.
- **Shots are no longer missed.** 1.1.0 asked "is the player shooting" four times a second, and a shot
  is visible to the game for only a few frames. The question is now asked every frame and latched.
- **Enemies are found in busy places.** The game hands out its ped list in pool order, not by
  distance; 1.1.0 asked for the first 32 entries and so, with more peds loaded (a camp, a town),
  could miss a spawned enemy altogether - the "sometimes it switches, the third time it does not"
  in the test notes. The whole list is now read, filtered by distance, and the nearest
  `MaxPedsScanned` are asked the combat question.
- On a stock `weapons.ymt` the offset search could have tied the real reload field with fields that
  hold 1.00 in every weapon (the 1.1 log shows two of them, `0x032C` and `0x0330`). The search now
  requires the matches to cover different expected values (for stock data: both 1.00 and 1.30) and,
  among objects of the recognised class, counts a different value against an offset.
- `TimeBetweenBulletsInLoop`, when sectioned patching is switched on, is found from its fixed place
  in the reload block (0x24 bytes after `LoopRate`) when the generic search is undecided.
- Switching the mod back on with F7 always starts in CALM, as specified; 1.0 and 1.1 returned to the
  state from before the pause, whose detector decision was stale by then. If a fight is still on,
  the next poll moves to COMBAT at once.
- The three presets no longer contain `IgnoreVersionCheck`. 1.0.0 had added it to make them
  structurally identical to the main INI, which broke the project's own rule that a preset carries
  values and never a way to switch a safety check off (SR-07). Left out, the key takes its default
  (0) silently; it can still be set in your own INI.

### Added

- Every gun is switched, also those with no entry in the plugin's table: weapon data found by the
  class pass whose name is not listed is checked with the game (is it a gun?), named from the
  game's own label, and switched with the INI section of its base weapon by name prefix or with
  `[Defaults]` (`IncludeUnlistedGuns`, on by default). Mounted guns and bows are excluded.
- The High Roller (`WEAPON_REVOLVER_DOUBLEACTION_GAMBLER`) and the Navy crossover revolver are in the
  table; they use the Double-Action and Navy sections.
- One `plan:` line per weapon at start (and after F9): the value the game loaded and the CALM /
  COMBAT values it will get, so a single log is enough to check every weapon.
- A second overlay line with the gun in your hands and the reload rate the plugin has put there, or
  "not managed"; one log line the first time each gun is taken in hand.
- New keys, all optional (an INI without them gets the defaults): `[Signals] AttackingHumans`,
  `[Signals] ShootingSustainsCombat`, `[Memory] IncludeUnlistedGuns`,
  `[Memory] PatchSectionedReload`.

### Changed

- `LoopRate` and `TimeBetweenBulletsInLoop` are no longer written by default
  (`PatchSectionedReload = 0`). The 1.1 logs showed them at stock in the developer's game, so the
  shipped calm values were calibrated with those two at stock; writing them would make calm slower
  than measured. Switching them on is experimental.
- `Mode = auto`, slowed file, no `Combat_AnimReloadRate` in the INI: combat now uses the weapon's
  stock value from the table instead of leaving it slowed. A weapon with no stock reference counts
  as "stock" when the loaded value is faster than its `Calm_` value.
- `MaxPedsScanned` keeps its name and default (32) but means "how many of the nearest peds inside
  `ThreatRadius` are checked".
- LeMat calm rate 0.74 → 0.47 (realistic; hardcore 0.3133, subtle 0.7833): 0.74 gave about 10 s for
  nine chambers in game, faster per chamber than any other revolver; 0.47 solves to about 15 s,
  the Cattleman's pace.
- Page protection is never changed by the plugin any more. A target whose page is not already
  writable is not patched (in practice none: the weapon data lives in read-write heap memory).
- Log: a fight forced with F8 and no other signal is logged as `(forced by hotkey)` instead of
  `(none)`; at `debug` level every write logs the value written and the value read back.

### Removed

- Binding a weapon "by plausibility only" (1.1.0) - see Fixed.

## [1.1.0] - test build, not released

First update after the plugin ran in game (2026-10-19). Built and play-tested on 2026-10-20/22;
superseded by 1.2.0 before release.

### Fixed

- The on-screen state readout no longer flickers: RDR2's debug text lives for exactly one frame and
  is now drawn every frame (cached, re-formatted only when something on it changes).
- 1.0 changed page protection twice for every field it wrote; 1.1.0 changed it only when a page was
  not writable. (The hitch it was meant to remove turned out to come from the page *queries*, which
  1.1.0 kept - fixed in 1.2.0.)
- No needless rewrite when a fight resumes during the cooldown.
- Both offset searches (stock values and the calm values from the INI) run and the one with more
  exact per-weapon matches wins, so a slowed `weapons.ymt` no longer needs a manual offset. A forced
  offset binds against the value set actually found there.
- `ForceAnimReloadRateOffset = 0` (and the two sibling keys) means "auto", as the INI always said.
- The start-up scan begins once the world is on screen, after a short settle delay with a 120 s
  cap; it yields the CPU every 16 MB, and the thousands of system calls that followed it in 1.0 are
  gone.
- Hotkeys are read by the input thread from atomic copies, so re-reading the configuration can no
  longer race with a key press.

### Added

- 57 gun variants in the table instead of 24 base weapons (named, dual-wield, golden, exotic).
- The overlay shows `INIT` and `SCANNING` while the mod starts and the remaining cooldown.
- Every binding is logged as confirmed, plausible-only or dropped; a structure check (the name hash
  still at its address) before every write and every restore; timings of each switch and of the
  ped scan.

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

<!-- No link references: no release is tagged yet. Add the tag comparison links when v1.2.1 is
     tagged in the repository (1.0.0, 1.1.0 and 1.2.0 were never released). -->
