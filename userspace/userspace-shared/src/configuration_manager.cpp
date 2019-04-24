/**
 * @file
 *
 * Implementation of configuration_manager and configuration_unit.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "configuration_manager.h"
#include "type_config.h"
#include <assert.h>
#include <map>

namespace
{

configuration_manager* s_instance = nullptr;

} // end namespace


configuration_manager& configuration_manager::instance()
{
	if(s_instance == nullptr)
	{
		s_instance = new configuration_manager();
	}

	return *s_instance;
}

void configuration_manager::init_config(const yaml_configuration& raw_config)
{
	for (const auto& config : m_config_map)
	{
		config.second->init(raw_config);
	}
}

void configuration_manager::print_config(const log_delegate& logger)
{
	for (const auto& config : m_config_map)
	{
		logger(config.second->to_string());
	}
}

void configuration_manager::register_config(configuration_unit* config)
{
	if (config == nullptr || config->get_key_string().size() == 0)
	{
		assert(false);
		return;
	}

	if (m_config_map.find(config->get_key_string()) != m_config_map.end())
	{
		assert(false);
		return;
	}

	m_config_map.emplace(config->get_key_string(), config);
}

void configuration_manager::deregister_config(configuration_unit* config)
{
	if (config == nullptr || config->get_key_string().size() == 0)
	{
		return;
	}

	m_config_map.erase(config->get_key_string());
}

bool configuration_manager::is_registered(configuration_unit* config)
{
	return m_config_map.find(config->get_key_string()) != m_config_map.end();
}

configuration_unit::configuration_unit(const std::string& key,
				       const std::string& subkey,
				       const std::string& subsubkey,
				       const std::string& description) :
	m_key(key),
	m_subkey(subkey),
	m_subsubkey(subsubkey),
	m_description(description)
{
	if (m_subkey.empty())
	{
		m_keystring = m_key;
	}
	else if (m_subsubkey.empty())
	{
		m_keystring = m_key + "." + m_subkey;
	}
	else
	{
		m_keystring = m_key + "." + m_subkey + "." + m_subsubkey;
	}

	configuration_manager::instance().register_config(this);
}

configuration_unit::~configuration_unit()
{
	configuration_manager::instance().deregister_config(this);
}

std::string configuration_unit::to_string() const
{
	return get_key_string() + ": " + value_to_string();
}

const std::string& configuration_unit::get_key_string() const
{
	return m_keystring;
}

const std::string& configuration_unit::get_key() const
{
	return m_key;
}

const std::string& configuration_unit::get_subkey() const
{
	return m_subkey;
}

const std::string& configuration_unit::get_subsubkey() const
{
	return m_subsubkey;
}

const std::string& configuration_unit::get_description() const
{
	return m_description;
}
