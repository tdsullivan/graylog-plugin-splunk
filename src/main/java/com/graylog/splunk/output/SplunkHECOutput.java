/**
 * This file is part of Graylog.
 *
 * Graylog is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Graylog is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Graylog.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.graylog.splunk.output;

import com.google.inject.Inject;
import com.google.inject.assistedinject.Assisted;
import com.graylog.splunk.output.senders.Sender;
import com.graylog.splunk.output.senders.HECSender;

import java.util.List;
import java.net.MalformedURLException;

import org.graylog2.plugin.Message;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.configuration.ConfigurationRequest;
import org.graylog2.plugin.configuration.fields.BooleanField;
import org.graylog2.plugin.configuration.fields.ConfigurationField;
import org.graylog2.plugin.configuration.fields.TextField;
import org.graylog2.plugin.inputs.annotations.ConfigClass;
import org.graylog2.plugin.inputs.annotations.FactoryClass;
import org.graylog2.plugin.outputs.MessageOutput;
import org.graylog2.plugin.outputs.MessageOutputConfigurationException;
import org.graylog2.plugin.streams.Stream;

public class SplunkHECOutput implements MessageOutput {

    private static final String CK_SPLUNK_URL = "splunk_url";
    private static final String CK_SPLUNK_HEC_TOKEN = "splunk_hec_token";
    private static final String CK_SPLUNK_HEC_VERIFY_SSL = "splunk_hec_verify_ssl";
    private static final String CK_SPLUNK_HEC_INDEX = "splunk_hec_index";
    private static final String CK_SPLUNK_HEC_SOURCETYPE = "splunk_hec_sourcetype";
    private static final String CK_SPLUNK_HEC_SOURCE = "splunk_hec_source";

    private boolean running = true;

    private final Sender sender;

    @Inject
    public SplunkHECOutput(@Assisted Configuration configuration) throws MessageOutputConfigurationException, MalformedURLException {
        // Check configuration.
        if (!checkConfiguration(configuration)) {
            throw new MessageOutputConfigurationException("Missing, or incomplete, configuration.");
        }

        // Set up sender.
        sender = new HECSender(
            configuration.getString(CK_SPLUNK_URL),
            configuration.getString(CK_SPLUNK_HEC_TOKEN),
            configuration.getBoolean(CK_SPLUNK_HEC_VERIFY_SSL, true),
            configuration.getString(CK_SPLUNK_HEC_INDEX, "main"),
            configuration.getString(CK_SPLUNK_HEC_SOURCETYPE, "input"),
            configuration.getString(CK_SPLUNK_HEC_SOURCE, "graylog")
        );

        running = true;
    }

    @Override
    public void stop() {
        sender.stop();
        running = false;
    }

    @Override
    public boolean isRunning() {
        return running;
    }

    @Override
    public void write(Message message) throws Exception {
        if (message == null || message.getFields() == null || message.getFields().isEmpty()) {
            return;
        }

        if(!sender.isInitialized()) {
            sender.initialize();
        }

        sender.send(message);
    }

    @Override
    public void write(List<Message> list) throws Exception {
        if (list == null) {
            return;
        }

        for(Message m : list) {
            write(m);
        }
    }

    public boolean checkConfiguration(Configuration c) {
        return c.stringIsSet(CK_SPLUNK_URL) && c.stringIsSet(CK_SPLUNK_HEC_TOKEN);
    }

    @FactoryClass
    public interface Factory extends MessageOutput.Factory<SplunkHECOutput> {
        @Override
        SplunkHECOutput create(Stream stream, Configuration configuration);

        @Override
        Config getConfig();

        @Override
        Descriptor getDescriptor();
    }

    @ConfigClass
    public static class Config extends MessageOutput.Config {
        @Override
        public ConfigurationRequest getRequestedConfiguration() {
            final ConfigurationRequest configurationRequest = new ConfigurationRequest();

            configurationRequest.addField(new TextField(
                            CK_SPLUNK_URL, "Splunk HEC URL", "",
                            "HEC URL",
                            ConfigurationField.Optional.NOT_OPTIONAL)
            );

            configurationRequest.addField(new TextField(
                            CK_SPLUNK_HEC_TOKEN, "Splunk HEC Token", "",
                            "HEC Token",
                            ConfigurationField.Optional.NOT_OPTIONAL)
            );

            configurationRequest.addField(new BooleanField(
                            CK_SPLUNK_HEC_VERIFY_SSL, "Verify SSL", true,
                            "Should SSL be verified")
            );

            configurationRequest.addField(new TextField(
                            CK_SPLUNK_HEC_INDEX, "Splunk Index", "main",
                            "Splunk index",
                            ConfigurationField.Optional.OPTIONAL)
            );

            configurationRequest.addField(new TextField(
                            CK_SPLUNK_HEC_SOURCETYPE, "Splunk Source Type", "input",
                            "Splunk sourcetype",
                            ConfigurationField.Optional.OPTIONAL)
            );

            configurationRequest.addField(new TextField(
                            CK_SPLUNK_HEC_SOURCE, "Splunk Source", "graylog",
                            "Splunk source",
                            ConfigurationField.Optional.OPTIONAL)
            );

            return configurationRequest;
        }
    }

    public static class Descriptor extends MessageOutput.Descriptor {
        public Descriptor() {
            super("Splunk HEC Output", false, "", "Writes messages to your Splunk installation via HEC input.");
        }
    }

}
