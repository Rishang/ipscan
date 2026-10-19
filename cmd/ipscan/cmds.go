// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"errors"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/noobi/ipscan-go/internal/config"
	"github.com/noobi/ipscan-go/internal/fetcher"
	"github.com/noobi/ipscan-go/internal/netutil"
	"github.com/noobi/ipscan-go/internal/pinger"
)

func newListFetchersCmd(o *scanOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "list-fetchers",
		Short: "List available columns (fetchers)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, _, err := o.loadConfig()
			if err != nil {
				return err
			}
			selected := map[string]bool{}
			for _, id := range cfg.Selected {
				selected[fetcher.Normalize(id)] = true
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 2, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tNAME\tDEFAULT\tDESCRIPTION")
			for _, f := range fetcher.All(cfg) {
				def := ""
				if selected[f.ID()] || f.ID() == "ip" {
					def = "yes"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.ID(), f.Name(), def, f.Description())
			}
			return tw.Flush()
		},
	}
}

func newListPingersCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list-pingers",
		Short: "List pinging methods and whether ICMP is available",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 2, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tDESCRIPTION")
			for _, n := range pinger.Names {
				fmt.Fprintf(tw, "%s\t%s\n", n, pinger.Descriptions[n])
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			if _, err := pinger.New(pinger.ICMP, 0); err != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "\nICMP: unavailable: %v\n", err)
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "\nICMP: available")
			}
			return nil
		},
	}
}

func newListInterfacesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list-interfaces",
		Short: "List local network interfaces and their networks",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ifs, err := netutil.Interfaces()
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 2, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "INTERFACE\tADDRESS\tNETWORK\tMAC\tSTATE")
			for _, ia := range ifs {
				state := "down"
				if ia.Up {
					state = "up"
				}
				if ia.Loopback {
					state += ",loopback"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", ia.Name, ia.Prefix, ia.Prefix.Masked(), ia.HardwareAddr, state)
			}
			return tw.Flush()
		},
	}
}

func newConfigCmd(o *scanOpts) *cobra.Command {
	c := &cobra.Command{
		Use:   "config",
		Short: "Show or create the configuration file",
	}
	c.AddCommand(&cobra.Command{
		Use:   "path",
		Short: "Print the configuration file location",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, path, err := o.loadConfigPath()
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), path)
			return nil
		},
	}, &cobra.Command{
		Use:   "show",
		Short: "Print the effective configuration (defaults merged with the file)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, _, err := o.loadConfig()
			if err != nil {
				return err
			}
			data, err := cfg.Marshal()
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(data)
			return err
		},
	})
	var force bool
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Write a configuration file with default values",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, path, err := o.loadConfigPath()
			if err != nil {
				return err
			}
			if _, err := os.Stat(path); err == nil && !force {
				return usagef("%s already exists (use --force to overwrite)", path)
			} else if err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			cfg := config.Default()
			cfg.Profiles = map[string]config.Profile{
				"example": {Targets: []string{"192.168.1.0/24"}, Fetchers: []string{"+mac", "+vendor"}},
			}
			if err := cfg.Save(path); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Wrote", path)
			return nil
		},
	}
	initCmd.Flags().BoolVar(&force, "force", false, "overwrite an existing file")
	c.AddCommand(initCmd)
	return c
}

// loadConfigPath resolves the config path without failing on parse errors.
func (o *scanOpts) loadConfigPath() (*config.Config, string, error) {
	path := o.configPath
	if path == "" {
		var err error
		if path, err = config.Path(); err != nil {
			return nil, "", err
		}
	}
	return nil, path, nil
}
