package ocm

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("OCM Internal", func() {
	Describe("When trying to load a configuration", func() {
		var (
			config         *Config
			configLocation string
			err            error
		)
		// JustBeforeEach executes before each of the following "when" statements.
		// This means: We run for each when statement "newConfigFromFile(configLocation)"
		// with a different configLocation as described in the BeforeEach() statements
		// in each "when" statement.
		JustBeforeEach(func() {
			config, err = newConfigFromFile(configLocation)
		})

		When("the client configuration exists", func() {
			BeforeEach(func() {
				configLocation = "../../test/ocm_test.json"
			})
			It("should load the configuration successfully", func() {
				Expect(config).To(Equal(&Config{
					AccessToken:  "DUMMYVALUE",
					ClientID:     "DUMMYVALUE",
					RefreshToken: "DUMMYVALUE",
					Scopes:       []string{"DUMMYVALUE"},
					TokenURL:     "DUMMYVALUE",
					URL:          "DUMMYVALUE",
				}))
			})
		})

		When("the client configuration does not exist", func() {
			BeforeEach(func() {
				configLocation = "invalid"
			})
			It("should return an empty configuration", func() {
				Expect(config).To(Equal(&Config{}))
			})
		})

		When("the client configuration is invalid", func() {
			BeforeEach(func() {
				configLocation = "../../test/ocm_test_invalid.json"
			})
			It("should fail to load the configuration", func() {
				Expect(err).Should(HaveOccurred())
			})
		})
	})
})
