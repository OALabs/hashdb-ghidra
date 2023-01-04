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
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.OptionalLong;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompilerLocation;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.tablechooser.AddressableRowObject;
import ghidra.app.tablechooser.StringColumnDisplay;
import ghidra.app.tablechooser.TableChooserDialog;
import ghidra.app.tablechooser.TableChooserExecutor;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.util.OperandFieldLocation;
import ghidra.util.exception.CancelledException;
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
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.SourceArchive;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;

import java.net.URL;
import java.security.SecureRandom;
import java.awt.event.ActionListener;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.event.ActionEvent;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JSpinner;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingWorker;
import javax.swing.border.EmptyBorder;

import org.python.util.PythonInterpreter;

public class HashDB extends GhidraScript {
	boolean HTTP_DEBUGGING = false;
	boolean GUI_DEBUGGING = false;
	boolean PY_DEBUGGING = false;

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

		private ArrayList<String> hunt(long[] hashes, double minimumHitcount) throws Exception {
			ArrayList<String> ret = new ArrayList<String>();
			JsonObject response = JsonParser
					.parseString(httpQuery("POST", "hunt", new Gson().toJson(new Hashes(hashes)).getBytes()))
					.getAsJsonObject();
			for (JsonElement hit : response.get("hits").getAsJsonArray()) {
				JsonObject row = hit.getAsJsonObject();
				if (minimumHitcount <= row.get("hitrate").getAsDouble()) {
					ret.add(row.get("algorithm").getAsString());
				}
			}

			return ret;
		}

		public class ApiHashInfo extends HashInfo {
			public String apiName;
			public String permutation;
			public String modules[];

			public ApiHashInfo(long hash, String apiName, String permutation, String[] modules) {
				super(hash);
				this.apiName = apiName;
				this.permutation = permutation;
				this.modules = modules;
			}

			@Override
			public String getResolutionName() {
				return apiName;
			}
		}

		public class NonApiHashInfo extends HashInfo {
			public String freeText;

			public NonApiHashInfo(long hash, String freeText) {
				super(hash);
				this.freeText = freeText;
			}

			@Override
			public String getResolutionName() {
				return freeText;
			}
		}

		public abstract class HashInfo {
			public long hash;

			public HashInfo(long hash) {
				this.hash = hash;
			}

			public abstract String getResolutionName();
		}

		private ArrayList<HashInfo> parseHashInfoFromJson(String httpResponse) {
			JsonObject response = JsonParser.parseString(httpResponse).getAsJsonObject();
			ArrayList<HashInfo> ret = new ArrayList<HashInfo>();
			for (JsonElement hashEntry : response.get("hashes").getAsJsonArray()) {
				JsonObject hashObject = hashEntry.getAsJsonObject();
				JsonObject stringInfo = hashObject.get("string").getAsJsonObject();
				long hash = hashObject.get("hash").getAsLong();
				if (stringInfo.get("is_api").getAsBoolean()) {
					/*-
					 * Example Responses:
					 * {"hashes": [{
					 *   "hash": 2937175076,
					 *   "string": {
					 *     "is_api": true,
					 *     "string": "RtlFreeHeap",
					 *     "permutation": "api",
					 *     "api": "RtlFreeHeap",
					 * 	   "modules": ["ntdll"]
					 *   }
					 * }]}
					 */
					String apiName = stringInfo.get("api").getAsString();
					String permutation = stringInfo.get("permutation").getAsString();
					JsonArray modulesArray = stringInfo.get("modules").getAsJsonArray();
					String[] modules = new String[modulesArray.size()];
					for (int i = 0; i < modules.length; i++) {
						modules[i] = modulesArray.get(i).getAsString();
					}
					ret.add(new ApiHashInfo(hash, apiName, permutation, modules));
				} else {
					/*-
					 * Example Responses:
					 * {"hashes": [{
					 *   "hash": 2227199552,
					 *   "string": {
					 *     "is_api": false
					 *     "string": "ntdll.dll",
					 *   }
					 * }]}
					 */
					ret.add(new NonApiHashInfo(hash, stringInfo.get("string").getAsString()));
				}
			}
			return ret;
		}

		private ArrayList<HashInfo> resolve(String algorithm, long hash, String permutation) throws Exception {
			ArrayList<HashInfo> ret = parseHashInfoFromJson(
					httpQuery("GET", String.format("hash/%s/%d", algorithm, hash)));
			ArrayList<HashInfo> filtered = new ArrayList<HashInfo>();
			for (HashInfo hashInfo : ret) {
				if (permutation != null && ApiHashInfo.class.isInstance(hashInfo)
						&& ((ApiHashInfo) hashInfo).permutation.compareTo(permutation) != 0)
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
				logDebugMessage(String.format("%s %s", method, urlString));
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
					logDebugMessage(String.format("HTTP Response: %s", response));
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

	public enum TransformInvertibility {
		NotInvertible, SelfInverse, Manual
	}

	public class GuiState {
		public TransformInvertibility transformInvertibility;

		public GuiState(TransformInvertibility transformInvertibility) {
			this.transformInvertibility = transformInvertibility;
		}
	}

	public enum OutputMethod {
		Enum, Struct
	}

	class HashTable extends TableChooserDialog {
		private JTextField enumNameTextField;
		private JTextField nonApiResolutionEnumName;
		private JTextField transformationInverseTextField;
		private JComboBox<String> transformationTextField;
		private JComboBox<String> hashAlgorithmField;
		private JComboBox<String> permutationField;
		private JTextField hashAlgorithmThresholdField;
		private GCheckBox resolveModulesCheckbox;
		private JTextField crawlFunctionName;
		private JSpinner crawlParameterIndex;
		private SpinnerNumberModel crawlParameterIndexModel;

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
			int index = 0;
			int count = permutationField.getItemCount();
			boolean exists = false;
			permutation = permutation.trim();
			for (index = 0; index < count; index++) {
				int stringDiff = permutation.compareTo(permutationField.getItemAt(index));
				if (stringDiff == 0) {
					exists = true;
					break;
				} else if (stringDiff < 0) {
					break;
				}
			}
			if (!exists)
				permutationField.insertItemAt(permutation, index);
			if (selectIt)
				permutationField.setSelectedItem(permutation);
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

		public String getNonApiEnumName() {
			return nonApiResolutionEnumName.getText();
		}

		public boolean resolveEntireModules() {
			return resolveModulesCheckbox.isSelected();
		}

		public double getAlgorithmThreshold() {
			try {
				double threshold = Double.parseDouble(hashAlgorithmThresholdField.getText());
				if (threshold < 0) {
					return 0;
				}
				if (threshold > 1.0) {
					return 1.0;
				}
				return threshold;
			} catch (NumberFormatException exception) {
				return 1;
			}
		}

		public GuiState getCurrentState() {
			if (transformationIsNotInvertibleCheckbox.isSelected())
				return new GuiState(TransformInvertibility.NotInvertible);
			if (transformationIsSelfInverseCheckbox.isSelected())
				return new GuiState(TransformInvertibility.SelfInverse);
			return new GuiState(TransformInvertibility.Manual);
		}

		public void enableComponentsAccordingToState(GuiState guiState) {
			switch (guiState.transformInvertibility) {
			case Manual:
				transformationInverseTextField.setEnabled(true);
				resolveModulesCheckbox.setEnabled(true);
				transformationIsSelfInverseCheckbox.setEnabled(true);
				break;
			case NotInvertible:
				transformationInverseTextField.setEnabled(false);
				resolveModulesCheckbox.setEnabled(false);
				transformationIsSelfInverseCheckbox.setEnabled(false);
				resolveModulesCheckbox.setSelected(false);
				break;
			case SelfInverse:
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
					} catch (ShowErrorInUi e) {
						return e.getMessage();
					} catch (Exception e) {
						logDebugMessage("Exception during resolution:", e);
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
			long maxWaitCount = 200;
			while (dialog.isBusy()) {
				try {
					Thread.sleep(10);
				} catch (Exception e) {
					logDebugMessage("Exception in waitAndClearSelection:", e);
					break;
				}
				if (maxWaitCount == 0) {
					logDebugMessage("UI Timeout in waitAndClearSelection.");
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

		private JComponent addQuerySettingsPanel() {
			TwoColumnPanel tc = new TwoColumnPanel(7);

			transformationTextField = new JComboBox<>();
			transformationTextField.setEditable(true);
			transformationTextField.addItem("X  # Unaltered Hash Value");
			transformationTextField.addItem("X ^ 0xBAADF00D  # XOR");
			transformationTextField.addItem("((((X ^ 0x76C7) << 0x10) ^ X) ^ 0xAFB9) & 0x1FFFFF  # REvil");
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

			JPanel hashAlgorithmLine = new JPanel(new BorderLayout(10, 10));
			hashAlgorithmField = new JComboBox<>();
			hashAlgorithmField.setEditable(true);
			hashAlgorithmLine.add(hashAlgorithmField, BorderLayout.CENTER);
			hashAlgorithmThresholdField = new JTextField(3);
			hashAlgorithmThresholdField.setText("1.0");
			hashAlgorithmThresholdField.addFocusListener(new FocusAdapter() {
				public void focusLost(FocusEvent e) {
					hashAlgorithmThresholdField.setText(String.format("%.1f", dialog.getAlgorithmThreshold()));
				}
			});
			hashAlgorithmLine.add(hashAlgorithmThresholdField, BorderLayout.EAST);

			tc.addRow("Hash Algorithm:", hashAlgorithmLine);

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

		private JComponent addOutputSettingsPanel() {
			int rowCount = 4;
			TwoColumnPanel tc = new TwoColumnPanel(rowCount);
			JPanel radioPanel = new JPanel(new BorderLayout(10, 0));

			enumNameTextField = new JTextField("HashDB");
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

			nonApiResolutionEnumName = new JTextField("HashDBStrings");
			tc.addRow("Enum for non-API resolutions", nonApiResolutionEnumName);

			return tc.getMain();
		}

		private JComponent addEditTablePanel() {
			JTextField manualHash = new JTextField();
			JButton addHashButton = new JButton("Add Hash");
			addHashButton.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent event) {

					final class HashAdder extends SwingWorker<Boolean, Object> {
						String hashValue;
						Address address;

						HashAdder(Address address, String hashValue) {
							this.hashValue = hashValue;
							this.address = address;
						}

						@Override
						protected Boolean doInBackground() throws Exception {
							return addHash(address, parseHash(hashValue));
						}

						@Override
						protected void done() {
							try {
								this.get();
							} catch (InterruptedException | ExecutionException e) {
								logDebugMessage(String.format("invalid hash value: %s", hashValue));
							}
						}
					}

					HashAdder adder = new HashAdder(currentAddress, manualHash.getText());
					adder.execute();
				}
			});
			JButton deleteSelectionButton = new JButton("Remove Selection");
			deleteSelectionButton.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent event) {
					for (AddressableRowObject row : dialog.getSelectedRowObjects()) {
						remove(row);
					}
				}
			});

			JPanel firstRow = new JPanel(new BorderLayout(10, 10));
			firstRow.add(new GDLabel("Hash"), BorderLayout.WEST);
			firstRow.add(manualHash, BorderLayout.CENTER);
			firstRow.add(addHashButton, BorderLayout.EAST);

			JPanel secondRow = new JPanel(new BorderLayout(10, 10));
			secondRow.add(deleteSelectionButton, BorderLayout.EAST);

			int rowCount = 2;
			JPanel topAlignedContents = new JPanel(new GridLayout(rowCount, 1));
			topAlignedContents.add(firstRow);
			topAlignedContents.add(secondRow);

			JPanel main = new JPanel(new BorderLayout());
			main.setBorder(new EmptyBorder(5, 2, 0, 2));
			main.add(topAlignedContents, BorderLayout.NORTH);
			return main;
		}

		@SuppressWarnings("unchecked")
		public void setCrawlFunctionParameterCount(Number count) {
			crawlParameterIndexModel.setMaximum((Comparable<Double>) count);
			crawlParameterIndexModel.setValue(count); // default select last parameter
		}

		private JComponent addScanFunctionPanel() {
			TwoColumnPanel tc = new TwoColumnPanel(3);

			crawlFunctionName = new JTextField("");
			tc.addRow("Function Name:", crawlFunctionName);

			crawlParameterIndexModel = new SpinnerNumberModel(1, 1, 3, 1);
			crawlParameterIndex = new JSpinner(crawlParameterIndexModel);
			tc.addRow("Parameter (1 based):", crawlParameterIndex);

			JButton scanButton = new JButton("Scan!");
			scanButton.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent event) {
					List<Function> functions = getGlobalFunctions(crawlFunctionName.getText());
					if (functions.size() == 0) {
						logDebugMessage("No function with this name found");
					} else if (functions.size() > 1) {
						logDebugMessage("Multiple functions with this name found");
					} else {
						TaskMonitor taskMonitor = getTaskMonitorComponent();
						showProgressBar("Scanning functions", true, true, 0);
						List<Address> calls = getCallAddresses(functions.get(0));
						taskMonitor.initialize(calls.size());
						final class Resolver extends SwingWorker<Void, Object> {
							@Override
							protected Void doInBackground() throws Exception {
								try {
									for (Address callAddr : calls) {
										try {
											OptionalLong hash = getConstantCallArgument(callAddr,
													(Integer) crawlParameterIndex.getValue());
											if (hash.isEmpty()) {
												logDebugMessage(String.format("Cannot extract value for call at 0x%x",
														callAddr.getOffset()));
											} else {
												addHash(callAddr, hash.getAsLong());
												if (GUI_DEBUGGING) {
													logDebugMessage(
															String.format("Found hash 0x%x passed to call at 0x%x",
																	hash.getAsLong(), callAddr.getOffset()));
												}
											}
										} catch (Exception e) {
											logDebugMessage(String.format(
													"Error while extracting parameter value from call at 0x%x",
													callAddr.getOffset()), e);
										}
										taskMonitor.incrementProgress(1);
										taskMonitor.checkCanceled();
									}
								} catch (CancelledException e) {
									logDebugMessage("Operation canceled");
								}
								return null;
							}

							@Override
							protected void done() {
								setStatusText(String.format("Scanned %d of %d function calls.",
										taskMonitor.getProgress(), calls.size()));
								hideTaskMonitorComponent();
								try {
									get();
								} catch (InterruptedException | ExecutionException e) {
									logDebugMessage("Unknown error during scanning", e);
								}
							}
						}
						Resolver resolver = new Resolver();
						resolver.execute();
					}
				}
			});
			tc.addRow(scanButton);

			return tc.getMain();
		}

		JTabbedPane McPane;

		protected void addWorkPanel(JComponent hauptPanele) {
			McPane = new JTabbedPane(); // McPane defies common camelCaseConventions
			super.addWorkPanel(hauptPanele);
			McPane.addTab("Query Settings", addQuerySettingsPanel());
			McPane.addTab("Output Settings", addOutputSettingsPanel());
			McPane.addTab("Edit Table", addEditTablePanel());
			McPane.addTab("Scan Function", addScanFunctionPanel());
			hauptPanele.add(McPane, BorderLayout.SOUTH);
			enableComponentsAccordingToState(getCurrentState());
		}

		public void openQuerySettingsTab() {
			McPane.setSelectedIndex(0);
		}

		public void openScanFunctionTab(Function function) {
			crawlFunctionName.setText(function.getName());
			setCrawlFunctionParameterCount(function.getParameterCount());
			McPane.setSelectedIndex(3);
		}

		public void setTransformationNotInvertible() {
			transformationIsNotInvertibleCheckbox.setSelected(true);
			enableComponentsAccordingToState(getCurrentState());
		}
	}

	static HashTable dialog = null;

	private void showDialog() {
		if (dialog == null) {
			if (GUI_DEBUGGING) {
				logDebugMessage("Creating new dialog.");
			}
			dialog = new HashTable(state.getTool(), new HashTableExecutor(), currentProgram, "HashDB is BestDB");
			configureTableColumns(dialog);
		}
		if (!dialog.isVisible()) {
			dialog.show();
		}

		state.getTool().showDialog(dialog);
	}

	private long parseHash(String input) throws Exception {
		if (input.length() == 0) {
			throw new Exception(String.format("Invalid input: %s (zero length)", input));
		}
		boolean endsInH = input.endsWith("h");
		boolean startsWith0x = input.startsWith("0x");
		if (endsInH) {
			input = input.substring(0, input.length() - 1);
		}
		if (startsWith0x) {
			return Long.parseLong(input.substring(2), 16);
		}
		if (endsInH) {
			return Long.parseLong(input, 16);
		}
		return Long.parseLong(input, 10);
	}

	private boolean addHash(Address address, long hash) {
		HashMap<Long, Address> hashes = new HashMap<Long, Address>();
		hashes.put(hash, address);
		return addHashes(hashes);
	}

	private boolean addHashes(HashMap<Long, Address> hashes) {
		dialog.selectAllRows();
		for (AddressableRowObject aro : dialog.getSelectedRowObjects()) {
			HashLocation hl = (HashLocation) aro;
			hashes.remove(hl.getHashAsLong());
		}
		for (Long hash : hashes.keySet()) {
			dialog.add(new HashLocation(hashes.get(hash), hash));
		}
		dialog.waitAndClearSelection();
		return true;
	}

	private void logDebugMessage(String msg) {
		logDebugMessage(msg, null);
	}

	private void logDebugMessage(String msg, Exception e) {
		String logOutput = String.format("[HashDB] %s", msg);
		if (e != null) {
			logOutput = String.format("%s %s", logOutput, getStackTraceAsString(e));
		}
		println(logOutput);
	}

	private DataType getDataType(String name, DataType fallback) {
		ArrayList<DataType> matchingDataTypes = new ArrayList<>();
		DataTypeManager dataTypeManager = currentProgram.getDataTypeManager();
		currentProgram.getDataTypeManager().findDataTypes(name, matchingDataTypes);
		if (matchingDataTypes.size() == 0) {
			AutoAnalysisManager am = AutoAnalysisManager.getAnalysisManager(currentProgram);
			DataTypeManagerService service = am.getDataTypeManagerService();
			for (SourceArchive a : dataTypeManager.getSourceArchives()) {
				String archiveName = a.getName();
				DataTypeManager dtm;
				try {
					dtm = service.openDataTypeArchive(archiveName);
				} catch (Exception e) {
					logDebugMessage(String.format("unable to open archive %s", archiveName), e);
					continue;
				}
				dtm.findDataTypes(name, matchingDataTypes);
				if (matchingDataTypes.size() > 0)
					break;
			}
		}
		if (matchingDataTypes.size() > 0)
			return matchingDataTypes.iterator().next();
		return fallback;
	}

	public void run() throws Exception {
		showDialog();
		LinkedHashMap<Long, Address> hashes = new LinkedHashMap<Long, Address>();
		if (currentSelection != null) {
			long nextCheckpoint = currentSelection.getMinAddress().getOffset();
			for (AddressRange addressRange : currentSelection.getAddressRanges(true)) {
				for (Address address : addressRange) {
					if (address.getOffset() < nextCheckpoint)
						continue;
					try {
						nextCheckpoint = getHashesAt(address, hashes).getOffset();
					} catch (Exception e) {
						logDebugMessage(String.format("Error parsing data at 0x%08X:", address.getOffset()), e);
					}
				}
			}
		} else {
			try {
				getHashesAtCurrentLocation(hashes);
			} catch (Exception e) {
				Function selectedFunction = getFunctionBefore(currentAddress.next());
				if (selectedFunction == null) {
					logDebugMessage("Error looking for hash values to add:", e);
				} else {
					logDebugMessage(
							String.format("No valid hash selected, interpreting selection as function to crawl: %s",
									selectedFunction.getName()));
					dialog.openScanFunctionTab(selectedFunction);
				}
				return;
			}
		}
		if (hashes.size() > 0) {
			dialog.openQuerySettingsTab();
			addHashes(hashes);
		}
	}

	public class DataTypeFactory {
		private OutputMethod strategy;
		private DataTypeManager dataTypeManager;
		private CategoryPath rootPath;

		public DataTypeFactory(OutputMethod strategy) {
			this.strategy = strategy;
			this.dataTypeManager = getCurrentProgram().getDataTypeManager();
			this.rootPath = new CategoryPath("/HashDB");
		}

		private DataType makeNew(String name) {
			switch (strategy) {
			case Struct:
				return new StructureDataType(rootPath, name, 0);
			case Enum:
			default:
				return new EnumDataType(rootPath, name, 4);
			}
		}

		private DataType getOutputType(String name) {
			DataType hashStorage = dataTypeManager.getDataType(new DataTypePath("/HashDB", name));
			if (hashStorage != null) {
				if (strategy == OutputMethod.Enum) {
					DataType copy = hashStorage.copy(dataTypeManager);
					if (copy instanceof EnumDataType) {
						return copy;
					}
				}
				logDebugMessage(String.format("A type named \"%s\" already exists; it will be overwritten.", name));
			}
			return makeNew(name);
		}

		private void putOutputType(DataType hashStorage) {
			dataTypeManager.addDataType(hashStorage, DataTypeConflictHandler.REPLACE_HANDLER);
		}

		private DataType commitApiResultsToStruct(HashResolutionResultStore store, String name) {
			StructureDataType dst = (StructureDataType) getOutputType(name);
			for (HashResolutionResult result : store.allResults()) {
				DataType entryDataType = null;
				String apiName = null;
				if (result.isResolved()) {
					apiName = result.getApiName();
					entryDataType = getDataType(apiName, null);
				}
				if (entryDataType == null) {
					entryDataType = getDataType("FARPROC", null);
				}
				if (entryDataType == null) {
					entryDataType = new FunctionDefinitionDataType("FARPROC");
				}
				entryDataType = PointerDataType.getPointer(entryDataType, currentProgram.getDefaultPointerSize());
				logDebugMessage(String.format("adding %s to %s", entryDataType.toString(), name));
				if (apiName == null) {
					dst.add(entryDataType);
				} else {
					dst.add(entryDataType, apiName, "");
				}
			}
			return dst;
		}

		public void commitDataType(DataType dst) {
			int id = currentProgram.startTransaction(String.format("updating data type \"%s\"", dst.getDisplayName()));
			try {
				putOutputType(dst);
			} finally {
				currentProgram.endTransaction(id, true);
			}
		}

		public void commitApiResults(String name, HashResolutionResultStore store) {
			DataType dst = null;
			switch (strategy) {
			case Enum:
				dst = commitResultsToEnum(store.resolvedResults(), name);
				break;
			case Struct:
				dst = commitApiResultsToStruct(store, name);
				break;
			}
			commitDataType(dst);
		}

		public DataType commitResultsToEnum(ArrayList<HashResolutionResult> results, String name) {
			DataType hashStorage = getOutputType(name);
			EnumDataType dst = (EnumDataType) hashStorage;
			for (HashResolutionResult result : results) {
				String apiName = result.getApiName();
				try {
					long oldValue = dst.getValue(apiName);
					if (oldValue != result.hashBeforeTransformation) {
						logDebugMessage(String.format(
								"%s contains duplicate entry %s with value 0x%08X, new value 0x%08X ignored.", name,
								apiName, oldValue, result.hashBeforeTransformation));
					}
				} catch (NoSuchElementException e) {
					dst.add(result.getApiName(), result.hashBeforeTransformation);
				}
			}
			return dst;
		}
	}

	private enum HashResolutionResultType {
		RESOLVED, NO_MATCHES_FOUND, HASH_COLLISION, NOT_AN_API_RESULT
	}

	private class HashResolutionResult {
		public ArrayList<HashDBApi.HashInfo> hashInfos;
		public long hashBeforeTransformation;

		HashResolutionResult(long hashBeforeTransformation) {
			this.hashBeforeTransformation = hashBeforeTransformation;
			this.hashInfos = new ArrayList<HashDBApi.HashInfo>();
		}

		HashResolutionResult(long hashBeforeTransformation, HashDBApi.HashInfo hashInfo) {
			this.hashBeforeTransformation = hashBeforeTransformation;
			this.hashInfos = new ArrayList<HashDBApi.HashInfo>();
			this.hashInfos.add(hashInfo);
		}

		HashResolutionResult(long hashBeforeTransformation, ArrayList<HashDBApi.HashInfo> hashInfos) {
			this.hashBeforeTransformation = hashBeforeTransformation;
			this.hashInfos = hashInfos;
		}

		public boolean isResolved() {
			return getType() == HashResolutionResultType.RESOLVED;
		}

		public boolean isApiResult() {
			switch (getType()) {
			case RESOLVED:
			case HASH_COLLISION:
				return true;
			default:
				return false;
			}
		}

		public boolean isCollision() {
			return getType() == HashResolutionResultType.HASH_COLLISION;
		}

		private HashResolutionResultType getType() {
			switch (hashInfos.size()) {
			case 0:
				return HashResolutionResultType.NO_MATCHES_FOUND;
			case 1:
				return HashDB.HashDBApi.ApiHashInfo.class.isInstance(hashInfos.iterator().next())
						? HashResolutionResultType.RESOLVED
						: HashResolutionResultType.NOT_AN_API_RESULT;
			default:
				return HashResolutionResultType.HASH_COLLISION;
			}

		}

		public String getApiName() {
			try {
				return hashInfos.iterator().next().getResolutionName();
			} catch (Exception e) {
				return null;
			}
		}

		public HashDBApi.HashInfo getSingleHashInfo() throws Exception {
			if (hashInfos.size() != 1)
				throw new Exception(
						String.format("This HashResolutionResult had %d HashInfo entries.", hashInfos.size()));
			return hashInfos.iterator().next();
		}
	}

	private class HashResolutionResultStore {
		private Map<Long, HashResolutionResult> store;

		HashResolutionResultStore() {
			store = new LinkedHashMap<Long, HashResolutionResult>();
		}

		public void addNoMatch(long hashBeforeTransform, long hashAfterTransform) {
			store.put(hashAfterTransform, new HashResolutionResult(hashBeforeTransform));
		}

		public void addCollision(long hashBeforeTransform, long hashAfterTransform,
				ArrayList<HashDBApi.HashInfo> hashInfos) {
			store.put(hashAfterTransform, new HashResolutionResult(hashBeforeTransform, hashInfos));
		}

		public void addResolution(long hashBeforeTransform, long hashAfterTransform, HashDBApi.HashInfo hashInfo) {
			store.put(hashAfterTransform, new HashResolutionResult(hashBeforeTransform, hashInfo));
		}

		public String getApiName(long hashAfterTransform) {
			try {
				return store.get(hashAfterTransform).getSingleHashInfo().getResolutionName();
			} catch (Exception e) {
				return null;
			}
		}

		public HashResolutionResult get(Long hashAfterTransform) {
			return store.get(hashAfterTransform);
		}

		public String prunePermutations() throws Exception {
			HashSet<String> matches = globallyMatchingPermutations();
			if (matches.size() == 0) {
				return null;
			}
			String match = matches.iterator().next();
			for (HashResolutionResult result : allResults()) {
				HashDBApi.HashInfo collected = null;
				if (!result.isApiResult()) {
					continue;
				}
				for (HashDBApi.HashInfo info : result.hashInfos) {
					if (HashDB.HashDBApi.ApiHashInfo.class.isInstance(info)
							&& ((HashDB.HashDBApi.ApiHashInfo) info).permutation.equals(match)) {
						collected = info;
					}
				}
				if (collected == null) {
					throw new Exception(
							String.format("The alleged global match %s was missing in a HashInfo instance", match));
				}
				result.hashInfos.clear();
				result.hashInfos.add(collected);
			}
			return match;
		}

		private HashSet<String> globallyMatchingPermutations() {
			HashMap<String, Long> permutationCounts = new HashMap<String, Long>();
			HashSet<String> globallyMatchingPermutations = new HashSet<String>();
			int apiResultCount = 0;

			for (HashResolutionResult result : allResults()) {
				if (!result.isApiResult()) {
					continue;
				}
				apiResultCount += 1;
				for (HashDBApi.HashInfo hashInfo : result.hashInfos) {
					if (HashDB.HashDBApi.ApiHashInfo.class.isInstance(hashInfo)) {
						HashDB.HashDBApi.ApiHashInfo apiHashInfo = (HashDB.HashDBApi.ApiHashInfo) hashInfo;
						Long oldCount = permutationCounts.get(apiHashInfo.permutation);
						if (oldCount == null)
							oldCount = 0L;
						permutationCounts.put(apiHashInfo.permutation, oldCount + 1L);
					}
				}
			}
			for (String key : permutationCounts.keySet()) {
				if (apiResultCount == permutationCounts.get(key))
					globallyMatchingPermutations.add(key);
			}
			return globallyMatchingPermutations;
		}

		public long resolvedCount() {
			return resolvedResults().size();
		}

		public ArrayList<HashResolutionResult> resolvedResults() {
			ArrayList<HashResolutionResult> ret = new ArrayList<HashResolutionResult>();
			for (HashResolutionResult result : allResults()) {
				if (result.isResolved()) {
					ret.add(result);
				}
			}
			return ret;
		}

		public ArrayList<HashResolutionResult> nonApiResolutions() {
			ArrayList<HashResolutionResult> ret = new ArrayList<HashResolutionResult>();
			for (HashResolutionResult result : allResults()) {
				if (!result.isApiResult()) {
					ret.add(result);
				}
			}
			return ret;
		}

		public Iterable<HashResolutionResult> allResults() {
			return store.values();
		}

		public boolean hasCollisions() {
			for (HashResolutionResult result : allResults()) {
				if (result.isCollision()) {
					return true;
				}
			}
			return false;
		}
	}

	public class ShowErrorInUi extends Exception {
		public ShowErrorInUi(String errorMessage) {
			super(errorMessage);
		}
	}

	private long[] transformHashes(ArrayList<HashDB.HashLocation> hashLocations) throws Exception {
		long[] ret = new long[hashLocations.size()];
		for (int k = 0; k < hashLocations.size(); k++) {
			long baseHash = hashLocations.get(k).getHashAsLong();
			ret[k] = transformHash(baseHash);
			if (dialog.isTransformationInvertible()) {
				long inverse = invertHashTransformation(ret[k]);
				if (inverse != baseHash) {
					if (!dialog.resolveEntireModules()) {
						dialog.setTransformationNotInvertible();
						logDebugMessage("This transformation is not invertible; I fixed it for you.");
					} else {
						throw new ShowErrorInUi(
								String.format("Transformation could not be inverted for hash 0x%08X.", baseHash));
					}
				}
			}
			if (GUI_DEBUGGING) {
				logDebugMessage(String.format("Translated hash for 0x%08X is 0x%08X.", baseHash, ret[k]));
			}
		}
		return ret;
	}

	private long initTaskMonitor(TaskMonitor tm) {
		long taskTotal = tm.getMaximum();
		long taskHunt = taskTotal / 2;
		if (taskHunt < 1) {
			taskHunt = 1;
		}
		taskTotal += taskHunt;
		tm.setMaximum(taskTotal);
		return taskHunt;
	}

	private String guessAlgorithm(TaskMonitor tm, long taskHunt, long[] hashesAfterTransform) throws Exception {
		tm.setMessage("guessing hash function");
		ArrayList<String> algorithms = new HashDBApi().hunt(hashesAfterTransform, dialog.getAlgorithmThreshold());
		if (algorithms.size() == 0) {
			throw new ShowErrorInUi("could not identify any hashing algorithms");
		} else if (algorithms.size() == 1) {
			String algorithm = algorithms.iterator().next();
			dialog.addNewHashAlgorithm(algorithm, true);
			tm.incrementProgress(taskHunt);
			return algorithm;
		} else {
			for (String a : algorithms)
				dialog.addNewHashAlgorithm(a, false);
			throw new ShowErrorInUi("please select an algorithm");
		}
	}

	private HashResolutionResultStore createResultStore(TaskMonitor tm, String algorithm,
			ArrayList<HashDB.HashLocation> hashLocations, long[] hashesAfterTransform) throws Exception {
		HashDBApi api = new HashDBApi();
		HashResolutionResultStore resultStore = new HashResolutionResultStore();
		HashSet<String> observedPermuations = new HashSet<String>();
		String permutation = dialog.getCurrentPermutation();
		for (int k = 0; k < hashesAfterTransform.length; k++) {
			HashLocation tableEntry = hashLocations.get(k);
			if (tm.isCancelled()) {
				break;
			}
			tm.setMessage(String.format("resolving hash 0x%08X (base value 0x%08x)", hashesAfterTransform[k],
					tableEntry.getHashAsLong()));
			String existingResolution = resultStore.getApiName(hashesAfterTransform[k]);
			if (existingResolution != null) {
				tableEntry.resolution = existingResolution;
				tm.incrementProgress(1);
				continue;
			}

			ArrayList<HashDBApi.HashInfo> resolved = api.resolve(algorithm, hashesAfterTransform[k], permutation);
			for (HashDBApi.HashInfo hi : resolved) {
				if (HashDB.HashDBApi.ApiHashInfo.class.isInstance(hi)) {
					HashDB.HashDBApi.ApiHashInfo ahi = (HashDB.HashDBApi.ApiHashInfo) hi;
					if (!observedPermuations.contains(ahi.permutation)) {
						observedPermuations.add(ahi.permutation);
						dialog.addNewPermutation(ahi.permutation, true);
					}
				}
			}

			if (resolved.size() == 0) {
				resultStore.addNoMatch(tableEntry.hashValue, hashesAfterTransform[k]);
				logDebugMessage(String.format("No resolution known for %s.", tableEntry.getHashValue()));
				tm.incrementProgress(1);
				continue;
			}

			if (resolved.size() > 1) {
				resultStore.addCollision(tableEntry.hashValue, hashesAfterTransform[k], resolved);
				if (GUI_DEBUGGING) {
					logDebugMessage(String.format("Hash collision for %s, skipping.", tableEntry.getHashValue()));
				}
				tm.incrementProgress(1);
				continue;
			}

			HashDBApi.HashInfo inputHashInfo = resolved.iterator().next();
			tableEntry.resolution = inputHashInfo.getResolutionName();
			if (HashDB.HashDBApi.ApiHashInfo.class.isInstance(inputHashInfo)) {
				HashDB.HashDBApi.ApiHashInfo apiInputHashInfo = (HashDB.HashDBApi.ApiHashInfo) inputHashInfo;
				if (apiInputHashInfo.modules != null && apiInputHashInfo.modules.length == 0) {
					resultStore.addResolution(tableEntry.hashValue, hashesAfterTransform[k], inputHashInfo);
					tm.incrementProgress(1);
					continue;
				}

				if (dialog.resolveEntireModules()) {
					for (String module : apiInputHashInfo.modules) {
						if (permutation != null && apiInputHashInfo.permutation.compareTo(permutation) != 0)
							continue;
						for (HashDBApi.HashInfo hashInfo : api.module(module, algorithm,
								apiInputHashInfo.permutation)) {
							resultStore.addResolution(invertHashTransformation(hashInfo.hash), hashInfo.hash, hashInfo);
						}
					}
				} else {
					resultStore.addResolution(tableEntry.hashValue, hashesAfterTransform[k], inputHashInfo);
				}
			} else if (HashDB.HashDBApi.NonApiHashInfo.class.isInstance(inputHashInfo)) {
				HashDB.HashDBApi.NonApiHashInfo nonApiInputHashInfo = (HashDB.HashDBApi.NonApiHashInfo) inputHashInfo;
				resultStore.addResolution(nonApiInputHashInfo.hash, hashesAfterTransform[k], inputHashInfo);
			}
			tm.incrementProgress(1);
		}

		return resultStore;
	}

	private void handleCollisions(TaskMonitor tm, ArrayList<HashDB.HashLocation> hashLocations,
			long[] hashesAfterTransform, HashResolutionResultStore resultStore) throws Exception {
		tm.setMessage("pruning permutation collisions");
		String match = resultStore.prunePermutations();
		if (match != null) {
			for (int k = 0; k < hashesAfterTransform.length; k++) {
				HashResolutionResult result = resultStore.get(hashesAfterTransform[k]);
				if (result.isResolved()) {
					HashLocation tableEntry = hashLocations.get(k);
					tableEntry.resolution = result.getSingleHashInfo().getResolutionName();
				}
			}
			dialog.addNewPermutation(match, true);
			logDebugMessage(String.format("The permutation \"%s\" was auto-selected because it matched all.", match));
		} else {
			logDebugMessage("Permutations could not be disambiguated, please select one manually.");
		}
	}

	private String resolveHashes(ArrayList<HashDB.HashLocation> hashLocations, TaskMonitor tm) throws Exception {
		long[] hashesAfterTransform = transformHashes(hashLocations);
		String algorithm = dialog.getCurrentHashAlgorithm();

		long taskHunt = initTaskMonitor(tm);
		if (algorithm == null) {
			algorithm = guessAlgorithm(tm, taskHunt, hashesAfterTransform);
		}
		HashResolutionResultStore resultStore = createResultStore(tm, algorithm, hashLocations, hashesAfterTransform);
		if (resultStore.hasCollisions()) {
			handleCollisions(tm, hashLocations, hashesAfterTransform, resultStore);
		}
		tm.setMessage(String.format("updating data type \"%s\"", dialog.getStorageName()));
		return processResult(resultStore);
	}

	private String processResult(HashResolutionResultStore resultStore) throws Exception {
		DataTypeFactory dataTypeFactory = new DataTypeFactory(dialog.getOutputMethod());
		String hashStorageName = dialog.getStorageName();
		String nonApiEnumName = dialog.getNonApiEnumName();
		StringBuilder sb = new StringBuilder();
		ArrayList<HashResolutionResult> nonApiResolutions = resultStore.nonApiResolutions();
		if (nonApiResolutions.size() > 0) {
			dataTypeFactory.commitDataType(dataTypeFactory.commitResultsToEnum(nonApiResolutions, nonApiEnumName));
			sb.append(String.format("Added %d values to data type \"%s\". ", nonApiResolutions.size(), nonApiEnumName));
		}
		if (resultStore.resolvedCount() > 0) {
			dataTypeFactory.commitApiResults(hashStorageName, resultStore);
			sb.append(String.format("Added %d values to data type \"%s\". ", resultStore.resolvedCount(),
					hashStorageName));
		}
		if (resultStore.hasCollisions() && dialog.getCurrentPermutation() == null) {
			sb.append("Select a permutation to resolve remaining hashes. ");
		}
		return sb.toString().trim();
	}

	private long transformHash(long hash) throws Exception {
		return applyTransformation(hash, dialog.getTransformation());
	}

	private long invertHashTransformation(long hash) throws Exception {
		return applyTransformation(hash, dialog.getTransformationInverse());
	}

	private long applyTransformation(long hash, String transformation) throws Exception {
		PythonInterpreter interp = new PythonInterpreter();
		interp.set("X", hash);
		long result = interp.eval(transformation).asLong();
		interp.close();
		if (result < 0) {
			result = 0xFFFFFFFFL - ~result;
		}
		if (PY_DEBUGGING) {
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

	private Address getHashesAt(Address address, HashMap<Long, Address> hashes) throws NotFoundException {
		Data data = currentProgram.getListing().getDataAt(address);
		if (data != null) {
			DataType dt = data.getDataType();
			if (dt instanceof Array) {
				Array array = (Array) dt;
				int elementSize = array.getElementLength();
				logDebugMessage(String.format("Parsing array containing %d hash values (%d bit each).",
						array.getNumElements(), elementSize * 8));
				for (int offset = 0; offset < array.getLength(); offset += elementSize) {
					long hash;
					try {
						hash = data.getBigInteger(offset, elementSize, false).longValue();
					} catch (MemoryAccessException e) {
						throw new NotFoundException();
					}
					hashes.put(hash, address.add(offset));
				}
				return address.add(array.getLength());
			}
			if (dt instanceof AbstractIntegerDataType) {
				try {
					hashes.put(data.getBigInteger(0, data.getDataType().getLength(), false).longValue(), address);
				} catch (MemoryAccessException e) {
					throw new NotFoundException();
				}
				return address.add(data.getLength());
			}
		}
		throw new NotFoundException();
	}

	private void getHashesAtCurrentLocation(HashMap<Long, Address> hashes) throws Exception {
		// First try to read the value of defined or undefined data. This covers many
		// different types of locations where the cursor could be in the data view.
		try {
			getHashesAt(currentLocation.getAddress(), hashes);
		} catch (NotFoundException e) {
			if (currentLocation instanceof DecompilerLocation) {
				Varnode varNode = ((DecompilerLocation) currentLocation).getToken().getVarnode();
				if (varNode == null)
					throw new Exception("You have to select something.");
				if (!varNode.isConstant())
					throw new Exception("You have to select a constant.");
				hashes.put(varNode.getOffset(), varNode.getPCAddress());
			} else if (currentLocation instanceof OperandFieldLocation) {
				OperandFieldLocation opLoc = (OperandFieldLocation) currentLocation;
				Address opAddress = opLoc.getAddress();
				Instruction instruction = currentProgram.getListing().getInstructionAt(opAddress);
				if (instruction == null)
					throw new Exception("Operand selected, but no instruction or data found.");
				Object[] args = instruction.getOpObjects(opLoc.getOperandIndex());
				int index = opLoc.getSubOperandIndex();
				if (index < args.length && args[index] instanceof Scalar) {
					Scalar scalar = (Scalar) args[index];
					hashes.put(scalar.getUnsignedValue(), opAddress);
				}
				throw new Exception("The selection is not a scalar value.");
			} else {
				throw new Exception(String.format("Don't know how to handle program location of type %s",
						currentLocation.getClass().getSimpleName()));
			}
		}
	}

	class UnknownVariableCopy extends Exception {
		public UnknownVariableCopy(PcodeOp unknownCode, Address addr) {
			super(String.format("unknown opcode %s for variable copy at %08X", unknownCode.getMnemonic(),
					addr.getOffset()));
		}
	}

	private OptionalLong getConstantCallArgument(Address addr, int argumentIndex)
			throws IllegalStateException, UnknownVariableCopy {
		Function caller = getFunctionBefore(addr);
		if (caller == null)
			throw new IllegalStateException();
		DecompInterface decompInterface = new DecompInterface();
		decompInterface.openProgram(currentProgram);
		DecompileResults decompileResults = decompInterface.decompileFunction(caller, 120, monitor);
		if (!decompileResults.decompileCompleted())
			throw new IllegalStateException();
		HighFunction highFunction = decompileResults.getHighFunction();
		Iterator<PcodeOpAST> pCodes = highFunction.getPcodeOps(addr);
		while (pCodes.hasNext()) {
			PcodeOpAST instruction = pCodes.next();
			if (instruction.getOpcode() == PcodeOp.CALL) {
				return traceVarnodeValue(instruction.getInput(argumentIndex));
			}
		}
		return OptionalLong.empty();
	}

	private OptionalLong traceVarnodeValue(Varnode argument) throws UnknownVariableCopy {
		while (!argument.isConstant()) {
			PcodeOp ins = argument.getDef();
			if (ins == null)
				break;
			switch (ins.getOpcode()) {
			case PcodeOp.CAST:
			case PcodeOp.COPY:
				argument = ins.getInput(0);
				break;
			case PcodeOp.PTRSUB:
			case PcodeOp.PTRADD:
				argument = ins.getInput(1);
				break;
			case PcodeOp.INT_MULT:
			case PcodeOp.MULTIEQUAL:
				// known cases where an array is indexed
				return OptionalLong.empty();
			default:
				// don't know how to handle this yet.
				throw new UnknownVariableCopy(ins, argument.getAddress());
			}
		}
		return OptionalLong.of(argument.getOffset());
	}

	private List<Address> getCallAddresses(Function deobfuscator) {
		List<Address> addresses = new ArrayList<Address>();
		for (Reference ref : getReferencesTo(deobfuscator.getEntryPoint())) {
			if (ref.getReferenceType() != RefType.UNCONDITIONAL_CALL)
				continue;
			addresses.add(ref.getFromAddress());
		}

		return addresses;
	}
}
