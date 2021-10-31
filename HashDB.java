//Script to look up API functions in HashDB (https://hashdb.openanalysis.net/)
//@author @larsborn @huettenhain
//@category HashDB
//@keybinding F3
//@menupath 
//@toolbar 

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import ghidra.app.decompiler.DecompilerLocation;
import ghidra.app.script.GhidraScript;
import ghidra.app.tablechooser.AddressableRowObject;
import ghidra.app.tablechooser.StringColumnDisplay;
import ghidra.app.tablechooser.TableChooserDialog;
import ghidra.app.tablechooser.TableChooserExecutor;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.util.OperandFieldLocation;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GDLabel;
import docking.widgets.table.TableSortState;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;

import java.net.URL;
import java.security.SecureRandom;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import javax.swing.ButtonGroup;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.SwingWorker;
import javax.swing.border.EmptyBorder;

public class HashDB extends GhidraScript {
	boolean HTTP_DEBUGGING = false;
	boolean GUI_DEBUGGING = false;
	boolean JS_DEBUGGING = false;

	static String getStackTraceAsString(Exception e) {
		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		e.printStackTrace(pw);
		return sw.toString();
	}

	private class HashDBApi {
		private String baseUrl = "https://hashdb.openanalysis.net";

		private class Hashes {
			@SuppressWarnings({ "unused" })
			public long[] hashes;

			public Hashes(long[] hashes) {
				this.hashes = hashes;
			}
		}

		private ArrayList<String> hunt(long[] hashes) throws Exception {
			ArrayList<String> ret = new ArrayList<String>();
			JsonObject response = JsonParser
					.parseString(httpQuery("POST", "hunt", new Gson().toJson(new Hashes(hashes)).getBytes()))
					.getAsJsonObject();
			for (JsonElement hit : response.get("hits").getAsJsonArray()) {
				ret.add(hit.getAsJsonObject().get("algorithm").getAsString());
			}

			return ret;
		}

		public class HashInfo {
			public long hash;
			public String apiName;
			public String permutation;
			public String modules[];

			public HashInfo(long hash, String apiName, String permutation, String modules[]) {
				this.hash = hash;
				this.apiName = apiName;
				this.permutation = permutation;
				this.modules = modules;
			}
		}

		private ArrayList<HashInfo> parseHashInfoFromJson(String httpResponse) {
			JsonObject response = JsonParser.parseString(httpResponse).getAsJsonObject();
			ArrayList<HashInfo> ret = new ArrayList<HashInfo>();
			for (JsonElement hashEntry : response.get("hashes").getAsJsonArray()) {
				JsonObject hashObject = hashEntry.getAsJsonObject();
				JsonObject stringInfo = hashObject.get("string").getAsJsonObject();
				if (!stringInfo.get("is_api").getAsBoolean())
					continue;
				JsonArray modulesArray = stringInfo.get("modules").getAsJsonArray();
				String[] modules = new String[modulesArray.size()];
				for (int i = 0; i < modules.length; i++) {
					modules[i] = modulesArray.get(i).getAsString();
				}
				if (!stringInfo.get("is_api").getAsBoolean()) {
					continue;
				}
				ret.add(new HashInfo(hashObject.get("hash").getAsLong(), stringInfo.get("api").getAsString(),
						stringInfo.get("permutation").getAsString(), modules));
			}
			return ret;
		}

		private ArrayList<HashInfo> resolve(String algorithm, long hash, String permutation) throws Exception {
			ArrayList<HashInfo> ret = parseHashInfoFromJson(
					httpQuery("GET", String.format("hash/%s/%d", algorithm, hash)));
			ArrayList<HashInfo> filtered = new ArrayList<HashInfo>();
			for (HashInfo hashInfo : ret) {
				if (permutation != null && hashInfo.permutation.compareTo(permutation) != 0)
					continue;
				if (hashInfo.hash != hash) {
					throw new Exception("hash mismatch");
				}
				filtered.add(hashInfo);
			}
			return filtered;
		}

		private ArrayList<HashInfo> module(String module, String algorithm, String permutation) throws Exception {
			return parseHashInfoFromJson(
					httpQuery("GET", String.format("module/%s/%s/%s", module, algorithm, permutation)));
		}

		private String httpQuery(String method, String endpoint) throws Exception {
			return httpQuery(method, endpoint, null);
		}

		private String httpQuery(String method, String endpoint, byte[] postData) throws Exception {
			String urlString = String.format("%s/%s", baseUrl, endpoint);
			if (HTTP_DEBUGGING) {
				println(String.format("[HashDB] %s %s", method, urlString));
			}
			URL url = new URL(urlString);
			SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
			sslContext.init(null, null, new SecureRandom());
			HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
			conn.setSSLSocketFactory(sslContext.getSocketFactory());

			conn.setInstanceFollowRedirects(true);
			conn.setDoOutput(true);
			conn.setRequestMethod(method);
			conn.setUseCaches(false);
			if (postData != null) {
				conn.setRequestProperty("Content-Type", "application/json; utf-8");
				conn.setRequestProperty("Content-Length", Integer.toString(postData.length));
				try (OutputStream wr = conn.getOutputStream()) {
					wr.write(postData);
				}
			}

			try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), "utf-8"))) {
				StringBuilder response = new StringBuilder();
				String responseLine = null;
				while ((responseLine = br.readLine()) != null) {
					response.append(responseLine.trim());
				}
				if (HTTP_DEBUGGING) {
					println(String.format("[HashDB] HTTP Response: %s", response));
				}
				return response.toString();
			}
		}
	}

	private class HashTableExecutor implements TableChooserExecutor {
		public HashTableExecutor() {

		}

		@Override
		public String getButtonName() {
			return "Query!";
		}

		@Override
		public boolean execute(AddressableRowObject rowObject) {
			return false;
		}

	}

	public enum GuiState {
		TransformationNotInvertible, TransformationSelfInverse, TransformationInverseManual
	}

	public enum OutputMethod {
		Enum, Struct
	}

	class HashTable extends TableChooserDialog {
		private JTextField enumNameTextField;
		private JTextField transformationInverseTextField;
		private JComboBox<String> transformationTextField;
		private JComboBox<String> hashAlgorithmField;
		private JComboBox<String> permutationField;
		private GCheckBox resolveModulesCheckbox;

		private GCheckBox transformationIsSelfInverseCheckbox;
		private GCheckBox transformationIsNotInvertibleCheckbox;

		private JRadioButton outputStructRadio;
		private JRadioButton outputEnumRadio;

		public HashTable(PluginTool tool, TableChooserExecutor executor, Program program, String title) {
			super(tool, executor, program, title, null, false);
			setFocusComponent(okButton);
			okButton.setMnemonic('Q');
		}

		@Override
		public void show() {
			super.show();
			setSortState(TableSortState.createUnsortedSortState());
		}

		@Override
		protected void setOkEnabled(boolean state) {
			return;
		}

		public OutputMethod getOutputMethod() throws IllegalStateException {
			if (outputStructRadio.isSelected())
				return OutputMethod.Struct;
			if (outputEnumRadio.isSelected())
				return OutputMethod.Enum;
			throw new IllegalStateException();
		}

		private String getComboBoxValue(JComboBox<String> box) {
			String currentText;
			try {
				currentText = box.getEditor().getItem().toString();
			} catch (Exception e1) {
				try {
					currentText = box.getSelectedItem().toString();
				} catch (Exception e2) {
					return null;
				}
			}
			if (currentText.isBlank())
				return null;
			return currentText.trim();
		}

		private void addToComboBox(JComboBox<String> box, String value, boolean selectIt) {
			boolean exists = false;
			if (value == null)
				return;
			value = value.trim();
			if (getComboBoxValue(box) == value)
				exists = true;
			for (int k = 0; !exists && k < box.getItemCount(); k++) {
				String item = box.getItemAt(k);
				if (item.compareTo(value) == 0)
					exists = true;
			}
			if (!exists)
				box.addItem(value);
			if (selectIt)
				box.setSelectedItem(value);
		}

		public void addNewPermutation(String permutation, boolean selectIt) {
			addToComboBox(permutationField, permutation, selectIt);
		}

		public String getCurrentPermutation() {
			return getComboBoxValue(permutationField);
		}

		public void addNewHashAlgorithm(String algorithm, boolean selectIt) {
			addToComboBox(hashAlgorithmField, algorithm, selectIt);
		}

		public String getCurrentHashAlgorithm() {
			return getComboBoxValue(hashAlgorithmField);
		}

		public String getTransformation() {
			return transformationTextField.getEditor().getItem().toString();
		}

		public boolean isTransformationInvertible() {
			return !transformationIsNotInvertibleCheckbox.isSelected();
		}

		public String getTransformationInverse() throws IllegalStateException {
			if (transformationIsNotInvertibleCheckbox.isSelected()) {
				throw new IllegalStateException();
			}
			if (transformationIsSelfInverseCheckbox.isSelected()) {
				return getTransformation();
			}
			return transformationInverseTextField.getText();
		}

		public String getStorageName() {
			return enumNameTextField.getText();
		}

		public boolean resolveEntireModules() {
			return resolveModulesCheckbox.isSelected();
		}

		public GuiState getCurrentState() {
			if (transformationIsNotInvertibleCheckbox.isSelected())
				return GuiState.TransformationNotInvertible;
			if (transformationIsSelfInverseCheckbox.isSelected())
				return GuiState.TransformationSelfInverse;
			return GuiState.TransformationInverseManual;
		}

		public void enableComponentsAccordingToState(GuiState guiState) {
			switch (guiState) {
			case TransformationInverseManual:
				transformationInverseTextField.setEnabled(true);
				resolveModulesCheckbox.setEnabled(true);
				transformationIsSelfInverseCheckbox.setEnabled(true);
				break;
			case TransformationNotInvertible:
				transformationInverseTextField.setEnabled(false);
				resolveModulesCheckbox.setEnabled(false);
				transformationIsSelfInverseCheckbox.setEnabled(false);
				resolveModulesCheckbox.setSelected(false);
				break;
			case TransformationSelfInverse:
				transformationInverseTextField.setEnabled(false);
				resolveModulesCheckbox.setEnabled(true);
				transformationIsSelfInverseCheckbox.setEnabled(true);
				break;
			}
		}

		public void selectAllRows() {
			selectRows(IntStream.range(0, getRowCount()).toArray());
		}

		@Override
		public void dispose() {
			selectAllRows();
			for (AddressableRowObject row : dialog.getSelectedRowObjects()) {
				remove(row);
			}
		}

		@Override
		protected void okCallback() {
			TaskMonitor tm = getTaskMonitorComponent();
			if (getSelectedRows().length == 0)
				selectAllRows();
			ArrayList<HashLocation> hashes = getSelectedRowObjects().stream().map(a -> (HashLocation) a)
					.collect(Collectors.toCollection(ArrayList::new));
			tm.initialize(hashes.size());
			showProgressBar("Querying HashDB", true, true, 0);

			final class Resolver extends SwingWorker<String, Object> {

				private final TaskMonitor taskMonitor;
				private final ArrayList<HashLocation> hashLocations;

				Resolver(ArrayList<HashLocation> hashLocations, TaskMonitor taskMonitor) {
					this.hashLocations = hashLocations;
					this.taskMonitor = taskMonitor;
				}

				@Override
				protected String doInBackground() throws Exception {
					try {
						return resolveHashes(hashLocations, taskMonitor);
					} catch (Exception e) {
						println(String.format("[HashDB] exception during resolution: %s\n", getStackTraceAsString(e)));
						return "unexpected error during resolution, see log";
					}
				}

				@Override
				protected void done() {
					String resultText;
					try {
						resultText = get();
					} catch (InterruptedException | ExecutionException e) {
						resultText = "unknown error during execution";
					}
					waitAndClearSelection();
					selectRows();
					hideTaskMonitorComponent();
					setStatusText(resultText);
				}
			}

			Resolver resolver = new Resolver(hashes, tm);
			resolver.execute();
		}

		public void waitAndClearSelection() {
			long maxWaitCount = 100;
			while (dialog.isBusy()) {
				try {
					Thread.sleep(10);
				} catch (Exception e) {
					println(String.format(getStackTraceAsString(e)));
				}
				if (maxWaitCount == 0) {
					if (GUI_DEBUGGING) {
						println("waitAndClearSelection ran into timeout");
					}
					break;
				}
				maxWaitCount--;
			}
			clearSelection();
		}

		public void parentOkCallback() {
			super.okCallback();
		}

		private class TwoColumnPanel {
			private JComponent left;
			private JComponent right;
			private JComponent main;

			public TwoColumnPanel(int rowCount) {
				left = new JPanel(new GridLayout(rowCount, 1));
				right = new JPanel(new GridLayout(rowCount, 1));
				main = new JPanel(new BorderLayout());
				main.setBorder(new EmptyBorder(5, 2, 0, 2));
				JPanel topAlignedContents = new JPanel(new BorderLayout(10, 10));
				main.add(topAlignedContents, BorderLayout.NORTH);
				topAlignedContents.add(left, BorderLayout.WEST);
				topAlignedContents.add(right, BorderLayout.CENTER);
			}

			public JComponent getMain() {
				return main;
			}

			public void addRow(JComponent component) {
				left.add(new GDLabel());
				right.add(component);
			}

			public void addRow(String label, JComponent component) {
				left.add(new GDLabel(label));
				right.add(component);
			}
		}

		protected JComponent addQuerySettingsPanel() {
			TwoColumnPanel tc = new TwoColumnPanel(7);

			transformationTextField = new JComboBox<>();
			transformationTextField.setEditable(true);
			transformationTextField.addItem("X /* Unaltered Hash Value */");
			transformationTextField.addItem("X ^ 0xBAADF00D /* XOR */");
			transformationTextField.addItem("((((X ^ 0x76C7) << 0x10) ^ X) ^ 0xAFB9) & 0x1FFFFF /*REvil*/");
			transformationTextField.setSelectedIndex(0);
			tc.addRow("Hash Transformation:", transformationTextField);

			final class UpdateButtons implements ActionListener {
				@Override
				public void actionPerformed(ActionEvent e) {
					enableComponentsAccordingToState(getCurrentState());
				}
			}

			UpdateButtons updateButtons = new UpdateButtons();

			transformationIsSelfInverseCheckbox = new GCheckBox("Transformation Is Self-Inverse");
			transformationIsSelfInverseCheckbox.addActionListener(updateButtons);
			tc.addRow(transformationIsSelfInverseCheckbox);

			transformationIsNotInvertibleCheckbox = new GCheckBox("Transformation Not Invertible");
			transformationIsNotInvertibleCheckbox.addActionListener(updateButtons);
			tc.addRow(transformationIsNotInvertibleCheckbox);

			transformationInverseTextField = new JTextField();
			tc.addRow("Transformation Inverse:", transformationInverseTextField);

			hashAlgorithmField = new JComboBox<>();
			hashAlgorithmField.setEditable(true);
			tc.addRow("Hash Algorithm:", hashAlgorithmField);

			permutationField = new JComboBox<>();
			permutationField.addItem("");
			permutationField.setSelectedIndex(0);
			tc.addRow("String Permutation:", permutationField);

			resolveModulesCheckbox = new GCheckBox("Resolve Entire Modules");
			tc.addRow(resolveModulesCheckbox);

			transformationIsSelfInverseCheckbox.setSelected(true);
			updateButtons.actionPerformed(null);

			return tc.getMain();
		}

		protected JComponent addOutputSettingsPanel() {
			TwoColumnPanel tc = new TwoColumnPanel(3);
			JPanel radioPanel = new JPanel(new BorderLayout(10, 0));

			enumNameTextField = new JTextField("HashDBEnum");
			tc.addRow("Data Type Name:", enumNameTextField);

			outputStructRadio = new JRadioButton("Generate Struct");
			outputStructRadio.setToolTipText(
					"The entries of the struct will have the same order as the items in the above table."
							+ " They will be named according to the resolved API symbols, or generically when no"
							+ " resolution was possible.");
			outputEnumRadio = new JRadioButton("Generate Enum");
			outputEnumRadio.setSelected(true);
			ButtonGroup group = new ButtonGroup();
			group.add(outputEnumRadio);
			group.add(outputStructRadio);
			radioPanel.add(outputEnumRadio, BorderLayout.WEST);
			radioPanel.add(outputStructRadio, BorderLayout.CENTER);
			tc.addRow(radioPanel);

			return tc.getMain();
		}

		protected JComponent addEditTablePanel() {
			// TwoColumnPanel tc = new TwoColumnPanel(2);
			return new JPanel(new BorderLayout());
		}

		protected JComponent addScanFunctionPanel() {
			return new JPanel(new BorderLayout());
		}

		protected void addWorkPanel(JComponent hauptPanele) {
			JTabbedPane McPane = new JTabbedPane(); // McPane defies common camelCaseConventions
			super.addWorkPanel(hauptPanele);
			McPane.addTab("Query Settings", addQuerySettingsPanel());
			McPane.addTab("Output Settings", addOutputSettingsPanel());
			McPane.addTab("Edit Table", addEditTablePanel());
			McPane.addTab("Scan Function", addScanFunctionPanel());
			hauptPanele.add(McPane, BorderLayout.SOUTH);
		}

		public void setTransformationNotInvertible() {
			transformationIsNotInvertibleCheckbox.setSelected(true);
			enableComponentsAccordingToState(getCurrentState());
		}
	}

	static HashTable dialog = null;

	private void showDialog() {
		if (dialog == null) {
			println("[HashDB] Creating new dialog.");
			dialog = new HashTable(state.getTool(), new HashTableExecutor(), currentProgram, "HashDB is BestDB");
			configureTableColumns(dialog);
		}
		if (!dialog.isVisible()) {
			dialog.show();
		}

		state.getTool().showDialog(dialog);
	}

	private boolean addHash(Address address, long hash) {
		dialog.selectAllRows();
		for (AddressableRowObject aro : dialog.getSelectedRowObjects()) {
			HashLocation hl = (HashLocation) aro;
			if (hl.getHashAsLong() == hash) {
				dialog.waitAndClearSelection();
				return false;
			}
		}

		dialog.add(new HashLocation(address, hash));
		dialog.waitAndClearSelection();
		return true;
	}

	public void run() throws Exception {
		showDialog();
		if (currentSelection != null) {
			for (AddressRange addressRange : currentSelection.getAddressRanges(true)) {
				for (Address address : addressRange) {
					try {
						addHash(address, getHashAt(address));
					} catch (NotFoundException e) {
					}
				}
			}
		} else {
			try {
				addHash(currentAddress, getSelectedHash());
			} catch (Exception e) {
				println(String.format("[HashDB] Error: %s", getStackTraceAsString(e)));
				return;
			}
		}
	}

	public class DataTypeFactory {
		private OutputMethod strategy;
		private DataTypeManager dataTypeManager;

		public DataTypeFactory(OutputMethod strategy) {
			this.strategy = strategy;
			this.dataTypeManager = getCurrentProgram().getDataTypeManager();
		}

		public DataType get(String hashStorageName) throws Exception {
			DataType hashStorage = dataTypeManager.getDataType(new DataTypePath("/HashDB", hashStorageName));

			switch (strategy) {
			case Enum:
				if (hashStorage == null) {
					hashStorage = new EnumDataType(new CategoryPath("/HashDB"), hashStorageName, 4);
				} else {
					DataType copy = hashStorage.copy(dataTypeManager);
					if (!(copy instanceof EnumDataType)) {
						throw new Exception(
								String.format("mismatching strategy: expected enum: %s", hashStorage.toString()));
					}
					hashStorage = copy;
				}
				break;
			case Struct:
				if (hashStorage == null) {
					hashStorage = new StructureDataType(new CategoryPath("/HashDB"), hashStorageName, 4);
				} else {
					if (!(hashStorage instanceof StructureDataType)) {
						throw new Exception(
								String.format("mismatching strategy: expected struct: %s", hashStorage.toString()));
					}
					hashStorage = hashStorage.copy(dataTypeManager);
				}
				break;
			}
			return hashStorage;
		}

		public void commit(DataType hashStorage) {
			dataTypeManager.addDataType(hashStorage, DataTypeConflictHandler.REPLACE_HANDLER);
		}

		public int onHashResolution(DataType hashStorage, HashDB.HashDBApi.HashInfo hashInfo, long baseHash) {
			try {
				switch (strategy) {
				case Enum:
					((EnumDataType) hashStorage).add(hashInfo.apiName, baseHash);
					break;
				case Struct:
					((StructureDataType) hashStorage).add(LongDataType.dataType, hashInfo.apiName, "");
					break;
				}
				return 1;
			} catch (IllegalArgumentException e) {
				if (GUI_DEBUGGING) {
					println(String.format("[HashDB] could not add %s (0x%08X) to %s: %s", hashInfo.apiName, baseHash,
							hashStorage.getDisplayName(), e.toString()));
				}
				return 0;
			}
		}
	}

	private String resolveHashes(ArrayList<HashDB.HashLocation> hashLocations, TaskMonitor tm) throws Exception {
		HashDBApi api = new HashDBApi();
		long[] hashes = new long[hashLocations.size()];
		for (int k = 0; k < hashLocations.size(); k++) {
			long baseHash = hashLocations.get(k).getHashAsLong();
			hashes[k] = transformHash(baseHash);
			if (dialog.isTransformationInvertible()) {
				long inverse = invertHashTransformation(hashes[k]);
				if (inverse != baseHash) {
					if (!dialog.resolveEntireModules()) {
						dialog.setTransformationNotInvertible();
						println("[HashDB] You lied. This transformation is not invertible. I fixed it for you.");
					} else {
						return String.format("Transformation could not be inverted for hash 0x%08X.", baseHash);
					}
				}
			}
			if (GUI_DEBUGGING) {
				println(String.format("[HashDB] Translated hash for 0x%08X is 0x%08X.", baseHash, hashes[k]));
			}
		}
		long taskTotal = tm.getMaximum();
		String algorithm = dialog.getCurrentHashAlgorithm();
		String permutation = dialog.getCurrentPermutation();

		if (algorithm == null) {
			long taskHunt = taskTotal / 2;
			if (taskHunt < 1) {
				taskHunt = 1;
			}
			taskTotal += taskHunt;
			tm.setMaximum(taskTotal);
			tm.setMessage("guessing hash function");
			ArrayList<String> algorithms = api.hunt(hashes);
			if (algorithms.size() == 0) {
				return "could not identify any hashing algorithms";
			} else if (algorithms.size() == 1) {
				algorithm = algorithms.iterator().next();
				dialog.addNewHashAlgorithm(algorithm, true);
			} else {
				for (String a : algorithms)
					dialog.addNewHashAlgorithm(a, false);
				return "please select an algorithm";
			}
			tm.incrementProgress(taskHunt);
		}

		int resolveCount = 0;
		String hashStorageName = dialog.getStorageName();
		String remark = "";
		DataTypeFactory dataTypeFactory = new DataTypeFactory(dialog.getOutputMethod());
		Map<Long, String> resolvedHashes = new HashMap<Long, String>();
		DataType hashStorage = dataTypeFactory.get(hashStorageName);

		for (int k = 0; k < hashes.length; k++) {
			HashLocation hl = hashLocations.get(k);
			if (tm.isCancelled())
				break;
			tm.setMessage(String.format("resolving hash 0x%08X (base value 0x%08x)", hashes[k], hl.getHashAsLong()));

			if (resolvedHashes.containsKey(hashes[k])) {
				hl.resolution = resolvedHashes.get(hashes[k]);
				tm.incrementProgress(1);
				continue;
			}
			ArrayList<HashDB.HashDBApi.HashInfo> resolved = api.resolve(algorithm, hashes[k], permutation);
			for (HashDB.HashDBApi.HashInfo hi : resolved)
				dialog.addNewPermutation(hi.permutation, true);
			if (resolved.size() == 0) {
				continue;
			} else if (resolved.size() > 1) {
				println(String.format("[HashDB] Hash collision for %s, skipping.", hl.getHashValue()));
				if (permutation == null) {
					remark = "Select a permutation to resolve remaining hashes.";
				}
				continue;
			}

			HashDB.HashDBApi.HashInfo inputHashInfo = resolved.iterator().next();
			hl.resolution = inputHashInfo.apiName;

			if (inputHashInfo.modules.length == 0) {
				println(String.format("[HashDB] No modules found for %s (hash %s)", inputHashInfo.apiName,
						hl.getHashValue()));
			}

			if (dialog.resolveEntireModules()) {
				for (String module : inputHashInfo.modules) {
					if (permutation != null && inputHashInfo.permutation.compareTo(permutation) != 0)
						continue;
					for (HashDB.HashDBApi.HashInfo hashInfo : api.module(module, algorithm,
							inputHashInfo.permutation)) {
						resolveCount += dataTypeFactory.onHashResolution(hashStorage, hashInfo,
								invertHashTransformation(hashInfo.hash));
						resolvedHashes.put(hashInfo.hash, hashInfo.apiName);
					}
				}
			} else {
				resolveCount += dataTypeFactory.onHashResolution(hashStorage, inputHashInfo, hl.hashValue);
				resolvedHashes.put(inputHashInfo.hash, inputHashInfo.apiName);
			}

			if (tm != null) {
				tm.incrementProgress(1);
			}
		}
		tm.setMessage(String.format("updating data type %s", hashStorage.getDisplayName()));
		int id = currentProgram.startTransaction(String.format("updating enumeration %s", hashStorageName));
		dataTypeFactory.commit(hashStorage);

		currentProgram.endTransaction(id, true);
		return String.format("Added %d enum values to %s. %s", resolveCount, hashStorage.getDisplayName(), remark)
				.trim();
	}

	private long transformHash(long hash) throws ScriptException {
		return applyTransformation(hash, dialog.getTransformation());
	}

	private long invertHashTransformation(long hash) throws ScriptException {
		return applyTransformation(hash, dialog.getTransformationInverse());
	}

	private long applyTransformation(long hash, String transformation) throws ScriptException {
		ScriptEngineManager manager = new ScriptEngineManager();
		ScriptEngine engine = manager.getEngineByName("JavaScript");
		engine.put("X", hash);
		long result = Long.valueOf(engine.eval(transformation).toString());
		if (result < 0) {
			result = 0xFFFFFFFFL - ~result;
		}
		if (JS_DEBUGGING) {
			println(String.format("%d became %d", hash, result));			
		}		
		return result;
	}

	private void configureTableColumns(TableChooserDialog dialogToConfigure) {
		StringColumnDisplay hashColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "Hash";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				HashLocation row = (HashLocation) rowObject;
				return row.getHashValue();
			}

			@Override
			public int compare(AddressableRowObject o1, AddressableRowObject o2) {
				return getColumnValue(o1).compareTo(getColumnValue(o2));
			}
		};

		dialogToConfigure.addCustomColumn(hashColumn);
		StringColumnDisplay resolutionColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "Resolution";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				HashLocation row = (HashLocation) rowObject;
				return row.getResolution() == null ? "-" : row.getResolution();
			}

			@Override
			public int compare(AddressableRowObject o1, AddressableRowObject o2) {
				return getColumnValue(o1).compareTo(getColumnValue(o2));
			}
		};

		dialogToConfigure.addCustomColumn(resolutionColumn);
	}

	class HashLocation implements AddressableRowObject {
		private Address address;
		private long hashValue;
		private String resolution;

		HashLocation(Address address, long hashValue) {
			this.address = address;
			this.hashValue = hashValue;
			this.resolution = null;
		}

		@Override
		public Address getAddress() {
			return address;
		}

		public long getHashAsLong() {
			return hashValue;
		}

		public String getHashValue() {
			return String.format("%08x", hashValue);
		}

		public String getResolution() {
			return this.resolution;
		}
	}

	private long getHashAt(Address address) throws NotFoundException {
		Data data = currentProgram.getListing().getDataAt(address);
		if (data != null) {
			try {
				return data.getBigInteger(0, data.getDataType().getLength(), false).longValue();
			} catch (MemoryAccessException e) {
			}
		}
		throw new NotFoundException();
	}

	private long getSelectedHash() throws Exception {
		// First try to read the value of defined or undefined data. This covers many
		// different types of locations where the cursor could be in the data view.
		try {
			return getHashAt(currentLocation.getAddress());
		} catch (NotFoundException e) {
		}
		if (currentLocation instanceof DecompilerLocation) {
			Varnode varNode = ((DecompilerLocation) currentLocation).getToken().getVarnode();
			if (varNode == null || !varNode.isConstant())
				throw new Exception("You have to select a constant.");
			return varNode.getOffset();
		} else if (currentLocation instanceof OperandFieldLocation) {
			OperandFieldLocation opLoc = (OperandFieldLocation) currentLocation;
			Address opAddress = opLoc.getAddress();
			Instruction instruction = currentProgram.getListing().getInstructionAt(opAddress);
			if (instruction == null)
				throw new Exception("Operand selected, but no instruction or data found.");
			Object[] args = instruction.getOpObjects(opLoc.getOperandIndex());
			int index = opLoc.getSubOperandIndex();
			if (index < args.length && args[index] instanceof Scalar)
				return ((Scalar) args[index]).getUnsignedValue();
			throw new Exception("The selection is not a scalar value.");
		} else {
			throw new Exception(String.format("Don't know how to handle program location of type %s",
					currentLocation.getClass().getSimpleName()));
		}
	}
}
