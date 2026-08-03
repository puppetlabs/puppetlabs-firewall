# frozen_string_literal: true

require 'puppet_x'

module PuppetX::Firewall # rubocop:disable Style/ClassAndModuleChildren
  # A read cache for `iptables-save` style command output and its parsed form,
  # scoped to a single catalog application.
  #
  # The Resource API calls a provider's `get` method once for every resource of
  # that type in the catalog. Without caching that means one full
  # `iptables-save`/`ip6tables-save` execution and a full parse of the entire
  # ruleset per managed rule, per run. All of those reads happen within a single
  # catalog application against a ruleset that only this module is changing, so
  # they can safely share one snapshot.
  #
  # Scoping and invalidation:
  # - Entries are keyed to the object identity of Puppet's :current_environment
  #   context binding. The agent binds a fresh environment object for every
  #   catalog run, so a new run never observes a previous run's snapshot.
  # - Any provider action that changes rules or chains must call `invalidate`,
  #   which drops the whole cache so the next read re-executes the underlying
  #   command and observes the change.
  # - When no :current_environment binding is available caching is disabled and
  #   every read executes the underlying command, matching previous behaviour.
  class Cache
    class << self
      # Fetch the cached value for `key`, computing and caching the result of
      # the given block on a miss. Computes without caching when no run context
      # is available.
      def fetch(key)
        token = run_token
        return yield if token.nil?

        unless token.equal?(@run_token)
          @store = {}
          @run_token = token
        end

        @store.fetch(key) { @store[key] = yield }
      end

      # Drop all cached data. Must be called after any operation that modifies
      # rules or chains.
      def invalidate
        @store = {}
      end

      private

      # An object identifying the current catalog application. The agent and
      # apply applications bind a fresh Puppet::Node::Environment for every
      # run and pop it when the run finishes.
      def run_token
        Puppet.lookup(:current_environment) { nil }
      rescue StandardError
        nil
      end
    end
  end
end
