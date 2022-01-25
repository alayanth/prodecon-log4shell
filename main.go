// Copyright 2021 by LunaSec (owned by Refinery Labs, Inc)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package main

import (
	"os"

	"github.com/lunasec-io/lunasec/tools/log4shell/commands"
	"github.com/lunasec-io/lunasec/tools/log4shell/constants"
	"github.com/lunasec-io/lunasec/tools/log4shell/util"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"
)

func enableGlobalFlags(c *cli.Context) {
	verbose := c.Bool("verbose")
	debug := c.Bool("debug")

	if verbose || debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	if debug {
		// include file and line number when logging
		log.Logger = log.With().Caller().Logger()
	}

	jsonFlag := c.Bool("json")
	if !jsonFlag {
		// pretty print output to the console if we are not interested in parsable output
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}
}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	util.RunOnProcessExit(func() {
		util.RemoveCleanupDirs()
	})

	globalBoolFlags := map[string]bool{
		"verbose":         false,
		"json":            false,
		"debug":           false,
		"ignore-warnings": false,
	}

	setGlobalBoolFlags := func(c *cli.Context) error {
		for flag := range globalBoolFlags {
			if c.IsSet(flag) {
				globalBoolFlags[flag] = true
			}
		}
		return nil
	}

	app := &cli.App{
		Name:  "log4shell",
		Usage: "Identifica el impacto de la vulnerabilidad de log4shell (CVE-2021-44228).",
		Authors: []*cli.Author{
			{
				Name:  "lunasec",
				Email: "contact@lunasec.io",
			},
			{
				Name:  "dynet",
				Email: "daltamirano@dynet.com.mx",
			},
		},
		Version:     constants.Version,
		Description: "Identifica dependencias de código que son vulnerables a log4shell. Más información en https://log4shell.com.",
		Before:      setGlobalBoolFlags,
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "verbose",
				Usage: "Muestra más información durante la ejecución del comando.",
			},
			&cli.BoolFlag{
				Name:  "json",
				Usage: "Muestra los hallazgos en formato json.",
			},
			&cli.BoolFlag{
				Name:  "debug",
				Usage: "Muestra información util mientras se hace el depurado del CLI.",
			},
		},
		Commands: []*cli.Command{
			{
				Name:    "scan",
				Aliases: []string{"s"},
				Usage:   "Escanea directorios, pasados como argumentos, para archivos de tipo .jar y .war que contengan archivos .class que sean vulnerables a log4shell.",
				Before:  setGlobalBoolFlags,
				Flags: []cli.Flag{
					&cli.StringSliceFlag{
						Name:  "exclude",
						Usage: "Excluye subdirectorios del escaneo. Esta bandera es útil si hay directorios donde el usuario no tiene acceso o cuando se hace un escaneo en el directorio raíz.",
					},
					&cli.BoolFlag{
						Name:        "include-log4j1",
						Usage:       "Bandera para incluir en el escaneo vulnerabilidad para Log4j 1.x.",
						DefaultText: "false",
					},
					&cli.BoolFlag{
						Name:  "archives",
						Usage: "Only scan for known vulnerable archives. By default the CLI will scan for class files which are known to be vulnerable which will result in higher signal findings. If you are specifically looking for vulnerable Java archive hashes, use this option.",
					},
					&cli.BoolFlag{
						Name:  "processes",
						Usage: "Currently only available for Linux systems. Only scan running processes and the files that they have open. This option will greatly improve performance when only running processes are of concern (ex. containers).",
					},
					&cli.StringFlag{
						Name:  "version-hashes",
						Usage: "Ruta al archivo con los hashes de las versiones.",
					},
					&cli.StringFlag{
						Name:  "output",
						Usage: "Ruta al archivo de salida donde los hallazos se guardarán en formato JSON.",
					},
					&cli.BoolFlag{
						Name:  "verbose",
						Usage: "Muestra más información durante la ejecución del comando.",
					},
					&cli.BoolFlag{
						Name:  "ignore-warnings",
						Usage: "Do not display warnings, only show findings.",
					},
					&cli.BoolFlag{
						Name:  "no-follow-symlinks",
						Usage: "Disable the resolution of symlinks while scanning. Note: symlinks might resolve to files outside of the included directories and so this option might be useful if you strictly want to search in said directories.",
					},
					&cli.BoolFlag{
						Name:  "json",
						Usage: "Display findings in json format.",
					},
					&cli.BoolFlag{
						Name:  "debug",
						Usage: "Display helpful information while debugging the CLI.",
					},
				},
				Action: func(c *cli.Context) error {
					return commands.ScanCommand(c, globalBoolFlags, log4jLibraryHashes)
				},
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal().Err(err)
	}
}
