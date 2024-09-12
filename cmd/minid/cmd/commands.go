package cmd

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"

	dbm "github.com/cosmos/cosmos-db"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"cosmossdk.io/log"
	confixcmd "cosmossdk.io/tools/confix/cmd"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/debug"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/keys"
	"github.com/cosmos/cosmos-sdk/client/pruning"
	"github.com/cosmos/cosmos-sdk/client/rpc"
	"github.com/cosmos/cosmos-sdk/client/snapshot"
	"github.com/cosmos/cosmos-sdk/server"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	authcmd "github.com/cosmos/cosmos-sdk/x/auth/client/cli"
	genutilcli "github.com/cosmos/cosmos-sdk/x/genutil/client/cli"

	"github.com/cosmosregistry/chain-minimal/app"
	"github.com/cosmosregistry/chain-minimal/x/crypto/pqc"
	"github.com/cosmosregistry/chain-minimal/x/tx"
)

func initRootCmd(rootCmd *cobra.Command, txConfig client.TxConfig, basicManager module.BasicManager) {
	cfg := sdk.GetConfig()
	cfg.Seal()

	rootCmd.AddCommand(
		genutilcli.InitCmd(basicManager, app.DefaultNodeHome),
		debug.Cmd(),
		confixcmd.ConfigCommand(),
		pruning.Cmd(newApp, app.DefaultNodeHome),
		snapshot.Cmd(newApp),
	)

	server.AddCommands(rootCmd, app.DefaultNodeHome, newApp, appExport, func(startCmd *cobra.Command) {})

	// add keybase, auxiliary RPC, query, genesis, and tx child commands
	rootCmd.AddCommand(
		server.StatusCommand(),
		genutilcli.Commands(txConfig, basicManager, app.DefaultNodeHome),
		queryCommand(),
		txCommand(),
		keys.Commands(),
		genPQCKeyCmd(),
		signTxCmd(),
		verifyTxSignatureCmd(),
	)
}

func queryCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        "query",
		Aliases:                    []string{"q"},
		Short:                      "Querying subcommands",
		DisableFlagParsing:         false,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	cmd.AddCommand(
		rpc.ValidatorCommand(),
		server.QueryBlockCmd(),
		authcmd.QueryTxsByEventsCmd(),
		server.QueryBlocksCmd(),
		authcmd.QueryTxCmd(),
		server.QueryBlockResultsCmd(),
	)

	return cmd
}

func txCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        "tx",
		Short:                      "Transactions subcommands",
		DisableFlagParsing:         false,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	cmd.AddCommand(
		authcmd.GetSignCommand(),
		authcmd.GetSignBatchCommand(),
		authcmd.GetMultiSignCommand(),
		authcmd.GetMultiSignBatchCmd(),
		authcmd.GetValidateSignaturesCommand(),
		authcmd.GetBroadcastCommand(),
		authcmd.GetEncodeCommand(),
		authcmd.GetDecodeCommand(),
		authcmd.GetSimulateCmd(),
	)

	return cmd
}

// newApp is an appCreator
func newApp(logger log.Logger, db dbm.DB, traceStore io.Writer, appOpts servertypes.AppOptions) servertypes.Application {
	baseappOptions := server.DefaultBaseappOptions(appOpts)
	app, err := app.NewMiniApp(logger, db, traceStore, true, appOpts, baseappOptions...)
	if err != nil {
		panic(err)
	}

	return app
}

// appExport creates a new app (optionally at a given height) and exports state.
func appExport(
	logger log.Logger,
	db dbm.DB,
	traceStore io.Writer,
	height int64,
	forZeroHeight bool,
	jailAllowedAddrs []string,
	appOpts servertypes.AppOptions,
	modulesToExport []string,
) (servertypes.ExportedApp, error) {
	var (
		miniApp *app.MiniApp
		err     error
	)

	// this check is necessary as we use the flag in x/upgrade.
	// we can exit more gracefully by checking the flag here.
	homePath, ok := appOpts.Get(flags.FlagHome).(string)
	if !ok || homePath == "" {
		return servertypes.ExportedApp{}, errors.New("application home not set")
	}

	viperAppOpts, ok := appOpts.(*viper.Viper)
	if !ok {
		return servertypes.ExportedApp{}, errors.New("appOpts is not viper.Viper")
	}

	// overwrite the FlagInvCheckPeriod
	viperAppOpts.Set(server.FlagInvCheckPeriod, 1)
	appOpts = viperAppOpts

	if height != -1 {
		miniApp, err = app.NewMiniApp(logger, db, traceStore, false, appOpts)
		if err != nil {
			return servertypes.ExportedApp{}, err
		}

		if err := miniApp.LoadHeight(height); err != nil {
			return servertypes.ExportedApp{}, err
		}
	} else {
		miniApp, err = app.NewMiniApp(logger, db, traceStore, true, appOpts)
		if err != nil {
			return servertypes.ExportedApp{}, err
		}
	}

	return miniApp.ExportAppStateAndValidators(forZeroHeight, jailAllowedAddrs, modulesToExport)
}

func genPQCKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gen-pqc-key [algorithm] --name [name]",
		Short: "Generate a PQC key (e.g., Dilithium2)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			algorithm := args[0]
			name := viper.GetString("name")
			pubKey, privKey, err := pqc.GenerateDilithiumKeyPair(algorithm)
			if err != nil {
				return fmt.Errorf("failed to generate key pair: %v", err)
			}

			// Store keys securely (e.g., in a file or keyring)
			err = saveKeys(name, pubKey, privKey)
			if err != nil {
				return err
			}
			fmt.Println("Generated and saved PQC keys for", name)
			return nil
		},
	}
	// Register the --name flag for the command
	cmd.Flags().String("name", "", "Name of user")
	cmd.MarkFlagRequired("name") // Ensure the flag is required
	return cmd
}

// func genPQCKeysCmd() *cobra.Command {
// 	return &cobra.Command{
// 		Use:   "gen-pqc-keys [algorithm]",
// 		Short: "Generate PQC keys (Dilithium) for Alice and Bob",
// 		RunE: func(cmd *cobra.Command, args []string) error {
// 			algorithm := args[0]
// 			// Generate key pair for Alice
// 			alicePubKey, alicePrivKey, err := pqc.GenerateDilithiumKeyPair(algorithm)
// 			if err != nil {
// 				return fmt.Errorf("failed to generate Alice's keys: %v", err)
// 			}

// 			err = saveKeys("alice", alicePubKey, alicePrivKey)
// 			if err != nil {
// 				return err
// 			}

// 			// Generate key pair for Bob
// 			bobPubKey, bobPrivKey, err := pqc.GenerateDilithiumKeyPair(algorithm)
// 			if err != nil {
// 				return fmt.Errorf("failed to generate Bob's keys: %v", err)
// 			}

// 			err = saveKeys("bob", bobPubKey, bobPrivKey)
// 			if err != nil {
// 				return err
// 			}

// 			fmt.Println("Generated and saved PQC keys for Alice and Bob.")
// 			return nil
// 		},
// 	}
// }

// saveKeys saves the generated public and private keys to files
func saveKeys(name string, pub pqc.DilithiumPublicKey, priv pqc.DilithiumPrivateKey) error {
	err := os.WriteFile(fmt.Sprintf("%s_private.key", name), priv.Key, 0600)
	if err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}
	err = os.WriteFile(fmt.Sprintf("%s_public.key", name), pub.Key, 0600)
	if err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}
	return nil
}

// sign-tx.go
func signTxCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign-tx [algorithm] [tx-bytes] --privkey [private-key-path]",
		Short: "Sign a transaction using a Dilithium private key",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			algorithm := args[0]
			txBytes, err := base64.StdEncoding.DecodeString(args[1])
			if err != nil {
				return fmt.Errorf("invalid transaction bytes: %v", err)
			}
			privKeyPath := viper.GetString("privkey")
			signature, err := tx.SignTx(algorithm, txBytes, privKeyPath)
			if err != nil {
				return fmt.Errorf("failed to sign transaction: %w", err)
			}

			fmt.Println(base64.StdEncoding.EncodeToString(signature))
			return nil
		},
	}
	// Register the --privkey flag for the command
	cmd.Flags().String("privkey", "", "Path to the private key file for signing")
	cmd.MarkFlagRequired("privkey") // Ensure the flag is required

	return cmd
}

// verify-tx-signature.go
func verifyTxSignatureCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify-tx-signature [algorithm] [tx-bytes] [signature] --pubkey [public-key-path]",
		Short: "Verify a transaction signature using a Dilithium public key",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			algorithm := args[0]
			txBytes, err := base64.StdEncoding.DecodeString(args[1])
			if err != nil {
				return fmt.Errorf("invalid transaction bytes: %v", err)
			}
			signature, err := base64.StdEncoding.DecodeString(args[2])
			if err != nil {
				return fmt.Errorf("invalid signature: %v", err)
			}
			pubKeyPath := viper.GetString("pubkey")
			valid, err := tx.VerifyTxSignature(algorithm, txBytes, signature, pubKeyPath)
			if err != nil {
				return fmt.Errorf("failed to verify transaction signature: %w", err)
			}

			if valid {
				fmt.Println("true")
			} else {
				fmt.Println("false")
			}
			return nil
		},
	}
	// Register the --privkey flag for the command
	cmd.Flags().String("pubkey", "", "Path to the public key file for verifying")
	cmd.MarkFlagRequired("pubkey") // Ensure the flag is required
	return cmd
}
