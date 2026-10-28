================================================================================
 RDR2 DYNAMIC RELOAD  1.2
 DynamicReloadSpeed.asi
================================================================================

WHAT IT DOES

  Out of combat, your character reloads slowly and deliberately - the way a man
  with time on his hands would. The moment a fight starts, reload speed goes
  back to normal, so the slow animation never gets you killed. When the fight
  is over and nothing hostile has happened for a few seconds, the slow reload
  comes back.

  It changes reload timing and nothing else: the weapon's AnimReloadRate, and -
  only if you switch it on (PatchSectionedReload = 1) - LoopRate and
  TimeBetweenBulletsInLoop. Damage, recoil, spread, ammo capacity, prices and
  every other weapon parameter are untouched.

  How it works, in one paragraph: the game reads its weapon data file once,
  while loading, so editing a file cannot change anything afterwards. This mod
  therefore finds the weapon data that is already loaded in the game's memory,
  takes a snapshot of the original values, and writes the profile that matches
  your current situation. The snapshot is restored when you switch the mod off,
  when the game shuts down, and on every error path. It never writes during a
  reload animation that is already playing, and a switch between the two speeds
  costs no noticeable frame time (since 1.2).

  Every gun is covered: the base weapons, their named and dual-wield variants,
  the weapons that have no entry in weapons.ymt at all (LeMat, Navy, M1899,
  Evans, Elephant Rifle, High Roller) and, since 1.2, guns the mod has no list
  entry for - it recognises weapon data by its structure, not only by name.


READ THIS FIRST - THREE THINGS YOU HAVE TO KNOW

  1. SINGLE PLAYER ONLY.
     Before entering Red Dead Online, delete DynamicReloadSpeed.asi. The
     plugin disabling itself does not remove the module from the game process.

  2. NPCs RELOAD FASTER TOO.
     Reload timing is global game data, not a per-character setting. There is
     no known way to change it for the player only. So in a gunfight your
     enemies reload at normal speed along with you, and out of combat they
     reload slowly along with you. This is a limitation, not a bug, and there
     is currently no fix for it.

  3. NO NETWORK, NO TELEMETRY.
     The mod makes no network connections and collects nothing. It writes one
     file - its own log, DynamicReloadSpeed.log, next to the .asi - and reads
     one file, its own .ini. That is the complete list.


REQUIREMENTS

  - ScriptHookRDR2
  - an ASI loader

  That is the whole list. You do NOT need a mod manager or mod loader
  framework, you do NOT need to edit or replace weapons.ymt, you do NOT need a
  font or localisation mod, and you do NOT need the Visual C++ redistributable
  (the plugin is built with a static runtime).

  Load the plugin ONE way only: either through the ASI loader (dinput8.dll) or
  through another tool's DLL list - not both. Loading the same file twice does
  no harm (Windows hands back the copy that is already loaded), but one way is
  easier to reason about when something needs checking.


INSTALL

  1. Install ScriptHookRDR2 and an ASI loader first, and make sure the game
     still starts.
  2. Unzip this archive into the game root - the folder that contains
     RDR2.exe. The archive contains four items and they all belong there:

         DynamicReloadSpeed.asi
         DynamicReloadSpeed.ini
         README.txt
         presets\

  3. Start the game, load a save, and check the log (see below).

  Nothing is copied into the game's own archives, and no game file is
  modified, renamed or replaced.


WHAT COUNTS AS A FIGHT

  COMBAT starts at once when any of these is true, and ends CooldownSeconds
  after the last of them stopped:

    - someone near you is fighting you (a gang, a wolf, a lawman)
    - you were hit recently
    - you are in a fist fight or shoved someone
    - you fired at a PERSON you were aiming at or locked on to
      (AttackingHumans; shooting a deer does not count)
    - the law is actively after you
    - with PlayerShooting = 1 (default): any shot at all

  While a fight is on, every shot you fire keeps it on (ShootingSustainsCombat),
  so a cooldown never kicks in between two shots: a shot counts for two
  seconds, and the cooldown starts two seconds after your last one. Hunters who
  want the slow reload while shooting game set PlayerShooting = 0 - shots at
  people still start a fight.


HOW TO CONFIRM IT LOADED

  Look for DynamicReloadSpeed.log next to DynamicReloadSpeed.asi.

  The first lines of that file report, in this order:

    - the plugin version
    - the configuration it parsed
    - which optional game signals are available on this build
    - the game build it detected - this line starts with "game build:" and
      shows the same four numbers as RDR2.exe -> Properties -> Details
    - how it recognised the weapon data ("weapon-info class recognised")
    - one "plan:" line per weapon: the value the game loaded and the CALM /
      COMBAT values that weapon will get

  With OnScreenState = 1 in [Debug] the state is also shown on screen: INIT and
  SCANNING while the mod starts (a few seconds after loading), then CALM,
  COMBAT or COOLDOWN with the time left, and on a second line the gun in your
  hands with the reload rate the mod has put there - or "not managed".

  Two revolvers or pistols drawn at once: two identical guns are one line
  ending in "x2" (they share one set of weapon data, so one reload rate); two
  different guns are two lines, the right hand first, the left hand below.
  A long gun carried lowered in the left hand is not shown - it cannot fire
  until you take it up again. Either way, every gun you hold reloads at its own
  CALM or COMBAT speed.

  If there is no log file at all, the plugin was never loaded and the problem
  is the ASI loader or ScriptHookRDR2, not this mod.

  ABOUT THE GAME BUILD CHECK

  The shipped DynamicReloadSpeed.ini has an EMPTY [Versions] list, and that is
  deliberate: a mod that does nothing on a clean install would be useless. With
  an empty list the plugin logs

      version check: no build list configured in [Versions], proceeding

  and carries on. Nothing is being skipped quietly - every other safety check
  still runs, and the mod still refuses to write anything it is not sure about.

  Once you have confirmed the mod works on your game, you can pin it: take the
  number from the "game build" line in the log and put it in the INI as

      Supported = <the number the log printed>

  Both the full form and the short form work, so for build 1.0.1491.50 either
  of these is accepted:

      Supported = 1.0.1491.50
      Supported = 1491.50

  From then on, a future game update changes the build number, the plugin logs
  "unsupported build", and it changes nothing until you check it again. That is
  a safety net you opt into, not something you have to do to get started.


HOTKEYS

  F7   Turn the whole mod off and on. Turning it off restores the original
       values immediately - no restart needed. "Original" means the values
       the game loaded at startup from the weapons.ymt you have installed:
       stock speed with a stock file, the slower speed with an overhaul or a
       file of your own that slows reloads. Turning it off also ends a fight
       forced with F8; turning it back on always starts in calm mode.
  F8   Force combat mode, for testing. Hold a rifle, press F8, reload, and you
       should see the fast reload. Press it again to stop forcing it; the mod
       then leaves combat the normal way, after the cooldown.
  F9   Re-read DynamicReloadSpeed.ini without restarting the game. Useful while
       tuning. It does NOT touch the snapshot of your original values, so F7
       still restores exactly what the game loaded at startup. The "plan:"
       lines are written again with the new values.

  The keys are configurable in the [Debug] section.


THE TWO SETTINGS MOST PEOPLE WILL WANT

  1. CooldownSeconds, in section [General]. Default 5.0.
     How long after the last sign of combat the slow reload comes back.
     Combat mode is entered instantly; only the way out is delayed. Raise it
     if a second wave of enemies keeps catching you mid-slow-reload; lower it
     if the slow reload takes too long to return after a fight.

  2. Pick a preset from the presets\ folder.
     Three complete configuration files are included. They differ only in how
     slow the out-of-combat reload is. Combat values are identical in all
     three and are the game's own stock values.

     They are in the presets\ folder next to this file:

         presets\subtle.ini      mild slowdown
         presets\realistic.ini   the default shipped values
         presets\hardcore.ini    strong slowdown

     To use one: back up your DynamicReloadSpeed.ini, then copy the preset
     over it and rename it to DynamicReloadSpeed.ini. Press F9 in game, or
     restart.

     Note: the presets deliberately contain no search-parameter section, no
     game build list and no switch that turns the build check off. If you had
     pinned a build number, copying a preset over your INI clears it, and the
     plugin goes back to "no build list configured, proceeding". Put the number
     back if you want that safety net.

     If you use your own slowed weapons.ymt, the CALM speed of every weapon in
     it is the one YOUR file loads; the mod then only switches those weapons to
     stock speed in a fight. The presets matter for the weapons your file does
     not slow.


AFTER A GAME UPDATE

  This mod contains no hard-coded addresses and no byte patterns. It finds the
  weapon data by the weapon's own name and by the shape of the game's weapon
  structure, and it measures where the reload field sits on YOUR machine,
  every time the game starts. That is why a game update does not normally
  require a new version of the mod.

  It also means the mod can fail to find what it needs. If the measurement
  does not agree with itself, the mod does nothing at all, writes the reason
  into the log, and leaves the game exactly as it was. It will never write a
  value to an address it is not sure about. A silent "no effect" with a reason
  in the log is the designed behaviour for that case, not a crash and not a
  guess.

  If you pinned a build number in [Versions], an update will make the plugin
  log "unsupported build" and do nothing until you check the new build and
  update that line. If you left the list empty, the plugin simply carries on
  and re-measures, as it does on every launch.


THE [Memory] SECTION

  [Memory] holds the search parameters the mod uses to locate and measure the
  reload fields, plus two switches: IncludeUnlistedGuns (also switch guns that
  have no section in the INI - on by default) and PatchSectionedReload
  (experimental, off by default). Everything else in it is for maintenance
  only: edit it only when the mod's maintainer tells you to after a game
  update. There is deliberately no setting in it that can name an address, and
  the shipped presets contain no [Memory] section at all.


UNINSTALL

  Delete these from the game root:

      DynamicReloadSpeed.asi
      DynamicReloadSpeed.ini
      README.txt
      presets\
      DynamicReloadSpeed.log

  Deleting DynamicReloadSpeed.asi alone is enough to stop the mod completely -
  the other files do nothing without it. No game file has to be restored or
  reinstalled, because none was ever changed.


TROUBLESHOOTING

  Read the log first. Every decision the mod makes is in there with the actual
  numbers behind it. Below, the left column is what you will find in
  DynamicReloadSpeed.log.

  ------------------------------------------------------------------------
  No log file at all
      The plugin was never loaded into the game.
      Check ScriptHookRDR2 and your ASI loader, and check that
      DynamicReloadSpeed.asi is in the same folder as RDR2.exe.

  "unsupported build"
      You pinned one or more build numbers in [Versions] and your game is not
      one of them, so the mod refused to change anything. Usually means the
      game updated. Copy the number from the "game build" line into
      [Versions] Supported and restart - or clear the line to go back to
      "no build list configured, proceeding".
      You will not see this on a clean install: the shipped INI ships with an
      empty list on purpose.

  "version check bypassed by user"
      You set IgnoreVersionCheck = 1. The build check is off; every other
      safety check still applies.

  "ini rejected: size limit"
      Your .ini is too large to be a real configuration, so it was ignored
      and built-in defaults were used. Replace it with a shipped preset.

  The log shows the plugin starting, but no "plan:" lines
      The mod could not confirm where the reload fields are and switched
      itself off on purpose. The game is untouched. Report the log - the
      resolver lines in it are exactly what is needed to diagnose it.

  "no weapon-info class could be confirmed"
      The mod could not recognise the weapon structure itself and fell back
      to matching exact values only. Weapons whose values it cannot confirm
      are left alone this session. Report the log.

  "hash not found in memory"
      That one weapon name does not exist in the game's data at all, so
      nothing can change its reload timing. Expected for a few names that are
      Online-only. Everything else keeps working.

  "mention(s) of the name in memory, none of them its weapon-info structure"
      The weapon exists, but its data structure was not found this launch.
      That one weapon keeps its normal speed. Report the log.

  "weapon in hand: ... a gun this plugin does NOT manage"
      Written the first time you hold such a gun. Report the line - it has the
      weapon's hash and the game's own name for it.

  "unlisted gun: ..."
      A gun with no section of its own in the INI was found and will be
      switched too (IncludeUnlistedGuns = 1). The line says which INI section
      it uses, or "defaults". Only hand-held firearms qualify - the game must
      call it a gun AND a revolver, pistol, repeater, rifle, shotgun or sniper
      rifle; "0 of them hand-held guns" is normal when the INI covers every
      gun you have.

  "offset rejected: out of window"
      A forced offset in [Memory] is outside the allowed range and was
      refused. Nothing was written. Remove the forced offset - it is not
      meant to be set by hand unless the log printed that value for you.

  "conditions: good only (stride unresolved)"
      Only with PatchSectionedReload = 1: the mod could only patch the
      clean-weapon block, not the worn-weapon ones. Nothing is broken.

  "deferred: reloading"
      A profile change landed while you were mid-reload, so the write was
      postponed until the reload finished, to avoid breaking the animation.
      Normal.

  "something else writes here"
      Another mod is writing the same reload field. The mod stops touching
      that one weapon and keeps working on the rest. If you use a weapon
      overhaul, set Mode = manual in [Profiles] for predictable behaviour.

  "restore skipped"
      One weapon's value could not be put back safely while restoring the
      original values (it was changed by something else, or the structure is
      gone), so nothing was written to it. The other weapons were restored
      normally. Restart the game to be sure of a clean state.

  "log size limit reached"
      The log hit MaxLogSizeMB and stopped being written. The mod keeps
      working. Delete the log file; if you had LogLevel = debug, set it back
      to info - debug is verbose and is not meant to be left on.
  ------------------------------------------------------------------------

  If you report a problem, attach DynamicReloadSpeed.log. It contains no
  personal data: file names are logged without folders, on purpose.


WHERE TO GET THIS MOD

  There are exactly two canonical sources:

    - the mod page on NexusMods (author RedziYT)
    - the Releases section of the GitHub repository
      PerepeliakDanylo/program-security--lab-2026-Danylo

  A file obtained from any other source is not supported by this project.
  Each release lists the SHA-256 of the archive and of DynamicReloadSpeed.asi
  so you can check what you downloaded.


LICENCE

  MIT. See LICENSE in the repository.
